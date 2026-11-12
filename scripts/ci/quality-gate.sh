#!/usr/bin/env bash
# The single quality gate. CI and the pre-push hook both run exactly this.
set -euo pipefail
cd "$(dirname "$0")/../.."

run() {
    echo "▶ $*"
    "$@"
}

# A cargo test command. In CI every target runs, and on a failure the failing
# tests and their first panic lines become annotations, shown on the run
# without reading its log (Actions keeps the first ten errors of a step).
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

# E2E_PART splits the end-to-end tests over two CI jobs where one would pass
# its time limit (Windows): part 2 runs only the modules named here, part 1
# runs everything else, so each test runs exactly once and a new module lands
# in part 1. Unset (every other runner, and locally) runs all of it in one.
E2E_PART=${E2E_PART:-}
E2E_SPLIT=(hosts:: cursor:: opencode:: hermes:: gemini_cli:: codex:: antigravity_cli::
    cline:: copilot_cli:: goose:: openclaw:: pi:: continue_cli:: proxy:: proxy_session::
    proxy_ca:: mcp:: mcp_gateway:: mcp_init_wrap:: mcp_startup:: mcp_status:: moatbench::
    differential::)
if [ "$E2E_PART" = 2 ]; then
    tests cargo test --locked -p openmoat --all-features --no-fail-fast --test e2e -- "${E2E_SPLIT[@]}"
    exit 0
fi

run cargo fmt --all --check
# fuzz/ is its own workspace (nightly, outside `--all`); rustfmt checks its
# targets on the pinned stable toolchain. CI's fuzz job runs clippy there.
run rustfmt --check --edition 2024 fuzz/fuzz_targets/*.rs
# GATE_LINT=0 (CI's macos-15-intel leg) leaves clippy and the docs to the
# macos-15 leg: the same OS, and no macOS code depends on the CPU, so the
# lints cannot differ; the slow Intel runner then spends its time on tests.
if [ "${GATE_LINT:-1}" != 0 ]; then
    run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    # Library and binary code may not unwrap, expect, panic or reach unreachable!;
    # tests may. Set here rather than in Cargo.toml so the helpers under `tests/`
    # keep their unwraps without an `#[allow]`.
    run cargo clippy --locked --workspace --lib --bins --all-features -- -D warnings \
        -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::unreachable
    run cargo doc --locked --workspace --no-deps --document-private-items
fi
if [ "$E2E_PART" = 1 ]; then
    # Everything but the end-to-end modules part 2 runs (see E2E_SPLIT).
    tests cargo test --locked --workspace --all-features --no-fail-fast --exclude openmoat
    tests cargo test --locked -p openmoat --all-features --no-fail-fast --bins
    skips=()
    for module in "${E2E_SPLIT[@]}"; do skips+=(--skip "$module"); done
    tests cargo test --locked -p openmoat --all-features --no-fail-fast --test e2e -- "${skips[@]}"
else
    tests cargo test --locked --workspace --all-features --no-fail-fast
fi
run cargo run -q --locked -p openmoat -- policy lint crates/openmoat-core/policies/default-v1.yaml
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    run cargo build -q --locked -p openmoat-core --target wasm32-unknown-unknown
else
    echo "▷ wasm32-unknown-unknown target not installed; purity build skipped (CI runs it)"
fi
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
    # CI's own decisions: which jobs a run needs, ci-ok, the release gate.
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
if command -v cargo-machete >/dev/null; then
    run cargo machete
else
    echo "▷ cargo-machete not installed; unused-dependency check skipped (CI runs it)"
fi
echo "✔ quality gate passed"
