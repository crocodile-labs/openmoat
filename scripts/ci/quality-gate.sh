#!/usr/bin/env bash
# The single quality gate. CI and the pre-push hook both run this.
#
# Locally, run it with no settings: every step, the tests whole. CI runs its
# steps in separate jobs (CONTRIBUTING "CI"), chosen with two settings:
#
#   GATE_STEPS      which steps run, any of
#                     fmt          rustfmt
#                     clippy       clippy, all targets, and the strict lints
#                     doc          rustdoc, warnings denied
#                     test         the tests (and doc tests)
#                     rust-checks  policy lint, wasm32 purity, unused deps
#                     checks       shellcheck, links, CI script tests, version
#                                  strings, changelog fragments, spelling
#                   (default: all). CI's `lint` job runs `checks` always and
#                   `fmt doc rust-checks` when code changed; each OS's test
#                   job `test`, and `clippy test` in its second part.
#   GATE_PARTITION  k/n: only the k-th of n parts of the tests (nextest's
#                   `--partition slice:k/n`; needs cargo-nextest). Doc tests
#                   run in part 1.
#
# The tests run under cargo-nextest when it is installed (.config/nextest.toml;
# NEXTEST_PROFILE=ci in CI: a time limit per test, one retry, a JUnit report),
# and under `cargo test` otherwise. Doc tests run under `cargo test --doc`.
set -euo pipefail
cd "$(dirname "$0")/../.."

STEPS=" ${GATE_STEPS:-fmt clippy doc test rust-checks checks} "
STEPS=${STEPS//,/ }
PARTITION=${GATE_PARTITION:-}

step() {
    [[ "$STEPS" == *" $1 "* ]]
}

run() {
    echo "▶ $*"
    "$@"
}

# A cargo test command. In CI the failing tests and their first panic lines
# become annotations, shown on the run without reading its log (Actions keeps
# the first ten errors of a step).
tests() {
    if [ -z "${GITHUB_ACTIONS:-}" ]; then
        run "$@"
        return
    fi
    echo "▶ $*"
    local log="${RUNNER_TEMP:-/tmp}/cargo-test.log"
    if ! "$@" 2>&1 | tee "$log"; then
        # Each panic with the line after it, which holds the message.
        { grep -E "^test .* FAILED$" "$log"; grep -A1 "panicked at" "$log" | grep -v '^--$'; } |
            head -10 | sed -e 's/%/%25/g' -e 's/^/::error title=cargo test::/'
        exit 1
    fi
}

# The workspace's tests under nextest, but those quarantined in
# .config/nextest-quarantine.md (the weekly workflow runs them on their own).
# A part that selects no test fails: a test binary compiled out on one OS
# cannot pass on nothing. In CI the run's JUnit report becomes the job
# summary: the failing tests with their first panic line, the flaky ones, the
# slowest (scripts/ci/junit_summary.py).
nextest() {
    local python filter
    # Windows runners may name Python `python`.
    python=$(command -v python3 || command -v python) ||
        { echo "python3 is needed to read .config/nextest-quarantine.md" >&2; exit 1; }
    filter=$("$python" -I scripts/ci/quarantine.py exclude)
    local args=(--locked --workspace --all-features --no-fail-fast --no-tests=fail -E "$filter")
    # `slice:` deals the tests out in turn, so the parts hold as many tests
    # each; `hash:` would keep a test in its part as others are added, but
    # leaves the parts uneven.
    [ -z "$PARTITION" ] || args+=(--partition "slice:$PARTITION")
    local status=0
    run cargo nextest run "${args[@]}" || status=$?
    local junit="target/nextest/${NEXTEST_PROFILE:-default}/junit.xml"
    if [ -n "${GITHUB_ACTIONS:-}" ] && [ -f "$junit" ]; then
        "$python" -I scripts/ci/junit_summary.py "$junit" || true
    fi
    [ "$status" -eq 0 ] || exit "$status"
}

if step fmt; then
    run cargo fmt --all --check
    # fuzz/ is its own workspace (nightly, outside `--all`); rustfmt checks its
    # targets on the pinned stable toolchain. CI's fuzz job runs clippy there.
    run rustfmt --check --edition 2024 fuzz/fuzz_targets/*.rs
fi
if step clippy; then
    run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    # Library and binary code may not unwrap, expect, panic or reach unreachable!;
    # tests may. Set here rather than in Cargo.toml so the helpers under `tests/`
    # keep their unwraps without an `#[allow]`.
    run cargo clippy --locked --workspace --lib --bins --all-features -- -D warnings \
        -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::unreachable
fi
if step doc; then
    run cargo doc --locked --workspace --no-deps --document-private-items
fi
if step test; then
    if cargo nextest --version > /dev/null 2>&1; then
        nextest
        if [ -z "$PARTITION" ] || [ "${PARTITION%%/*}" = 1 ]; then
            tests cargo test --locked --workspace --all-features --doc
        fi
    elif [ -n "$PARTITION" ]; then
        echo "GATE_PARTITION=$PARTITION needs cargo-nextest (scripts/ci/install-nextest.sh)" >&2
        exit 64
    else
        echo "▷ cargo-nextest not installed; the tests run under cargo test (CI runs nextest)"
        tests cargo test --locked --workspace --all-features --no-fail-fast
    fi
fi
if step rust-checks; then
    run cargo run -q --locked -p openmoat -- policy lint crates/openmoat-core/policies/default-v1.yaml
    if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
        run cargo build -q --locked -p openmoat-core --target wasm32-unknown-unknown
    else
        echo "▷ wasm32-unknown-unknown target not installed; purity build skipped (CI runs it)"
    fi
    if command -v cargo-machete >/dev/null; then
        run cargo machete
    else
        echo "▷ cargo-machete not installed; unused-dependency check skipped (CI runs it)"
    fi
fi
if step checks; then
    if command -v shellcheck >/dev/null; then
        echo "▶ shellcheck"
        git ls-files -z '*.sh' .githooks/pre-push | xargs -0 shellcheck
    else
        echo "▷ shellcheck not installed; shell script lint skipped (CI runs it)"
    fi
    if command -v python3 >/dev/null; then
        run python3 scripts/ci/check-links.py
        # The latest-agent check's records name the version each adapter was
        # checked against; this fails when that file no longer says so.
        run python3 -I scripts/ci/latest-agents/check.py records
        run python3 -I scripts/ci/latest-agents/test_after_call.py
        run python3 -I scripts/ci/latest-agents/test_check.py
        # CI's own decisions: which jobs a run needs, ci-ok, the release gate,
        # the quarantine, the test reports, the re-run of infrastructure failures.
        run python3 -I scripts/ci/test_ci_gates.py
    else
        echo "▷ python3 not installed; Markdown link check skipped (CI runs it)"
    fi
    # tomllib, which reads the manifests, is in the standard library from Python 3.11.
    if python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
        run python3 scripts/ci/check-versions.py
        run python3 scripts/changelog-check.py
    else
        echo "▷ python3 ≥ 3.11 needed; release version check skipped (CI runs it)"
    fi
    if command -v typos >/dev/null; then
        run typos
    else
        echo "▷ typos not installed; spell check skipped (CI runs it)"
    fi
fi
echo "✔ quality gate passed:${STEPS% }"
