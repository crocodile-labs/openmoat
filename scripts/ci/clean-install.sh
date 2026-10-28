#!/usr/bin/env bash
# The clean-machine install check (.github/workflows/clean-install.yml): the
# published release, installed the way a new user installs it, in a throwaway
# home, then walked through what the README tells them to do.
#
#   scripts/ci/clean-install.sh brew|shell|cargo
#
#   brew   `brew install crocodile-labs/tap/openmoat` (the README quick start's
#          own line, run as written)
#   shell  the cargo-dist shell installer of the latest GitHub release
#          (docs/INSTALL.md), downloaded to a file, its sha256 checked against
#          the release's sha256.sum and, with GH_TOKEN set, its build
#          attestation with `gh attestation verify`, then run with sh
#   cargo  `cargo install openmoat --locked` from crates.io
#
# Then, in order:
#   1. the README quick start (the blocks marked `ci:quickstart run`, read by
#      scripts/ci/readme-quickstart.py), each command as written: `openmoat init`
#      with no agent installed must say none was found, and `openmoat policy
#      check "cat ~/.ssh/id_rsa"` must deny with the output the README shows;
#   2. `openmoat demo`, `status` and `doctor`, each exiting 0;
#   3. Claude Code installed from npm (its native binary, lifecycle scripts
#      off) and started once against a local fake API, as a person's first
#      start creates ~/.claude; `openmoat init` without a terminal must then
#      name it and change nothing, `openmoat init --yes` must protect it;
#   4. the sha256 of every file under the home taken before that init;
#      `openmoat uninstall` (in a pseudo-terminal, as a person runs it) must
#      give each one back byte for byte, and `openmoat uninstall --purge` must
#      leave nothing of OpenMoat's: the home is then exactly as it was.
#
# The README's links and images are checked by the workflow's own job
# (scripts/ci/check-links.py --online README.md). With CLEAN_INSTALL_OUT set,
# every log is written there for the workflow's artefact.
set -euo pipefail

method=${1:?usage: clean-install.sh brew|shell|cargo}
case "$method" in
brew | shell | cargo) ;;
*)
    echo "clean-install: unknown install path $method" >&2
    exit 64
    ;;
esac
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
readme="$repo/README.md"
release_url=https://github.com/crocodile-labs/openmoat/releases/latest

# Taken before HOME moves: Rust's toolchains stay where the runner keeps them
# (the cargo path builds with them; they are not configuration).
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

# shellcheck disable=SC1091 # the library is linted as a file of its own
. "$repo/scripts/ci/lib/throwaway.sh"
root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/clean-install-$method.XXXXXX")
out=${CLEAN_INSTALL_OUT:-$root/out}
mkdir -p "$out"
throwaway_setup "$root"
# Homebrew's own cache and logs stay with the throwaway root, out of the home
# whose files are compared.
export HOMEBREW_CACHE="$root/brew-cache" HOMEBREW_LOGS="$root/brew-logs" HOMEBREW_NO_ANALYTICS=1
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
throwaway_refuse

step=setup
fake_pid=""
finish() {
    local code=$?
    [ -z "$fake_pid" ] || kill "$fake_pid" 2>/dev/null || true
    [ "$code" -eq 0 ] || echo "FAIL  clean install ($method) in step: $step"
    exit "$code"
}
trap finish EXIT

begin() {
    step=$1
    echo "== $step"
    throwaway_refuse
}

fail() {
    echo "FAIL  $*"
    exit 1
}

snapshot() {
    python3 -I "$repo/scripts/ci/tree-snapshot.py" "$@"
}

# run_logged <name> <command...>: output to $out/<name>.txt and shown; sets rc.
run_logged() {
    local name=$1
    shift
    rc=0
    "$@" </dev/null >"$out/$name.txt" 2>&1 || rc=$?
    cat "$out/$name.txt"
}

# The release a new user gets: the tag the releases page redirects to.
latest_tag() {
    local location
    location=$(curl -fsSI --retry 3 "$release_url" | tr -d '\r' | grep -i '^location:') || true
    printf '%s\n' "${location##*/tag/}"
}

begin "release"
tag=$(latest_tag)
case "$tag" in
v[0-9]*) echo "latest release: $tag" ;;
*) fail "no release tag from $release_url" ;;
esac

# ---- install ---------------------------------------------------------------

python3 -I "$repo/scripts/ci/readme-quickstart.py" commands "$readme" >"$out/quickstart.txt"
quickstart=()
while IFS= read -r line; do
    quickstart+=("$line")
done <"$out/quickstart.txt"
python3 -I "$repo/scripts/ci/readme-quickstart.py" output "$readme" >"$out/expected-policy-check.txt"

begin "install ($method)"
case "$method" in
brew)
    command -v brew >/dev/null || fail "no brew on PATH"
    # Right after a release the tap's formula is pushed by a later job of the
    # release workflow; CLEAN_INSTALL_WAIT_MINUTES (the workflow sets it on a
    # release) waits for it instead of testing the previous version.
    waited=0
    until curl -fsS --retry 3 -o "$root/openmoat.rb" \
        https://raw.githubusercontent.com/crocodile-labs/homebrew-tap/main/Formula/openmoat.rb &&
        grep -qF "version \"${tag#v}\"" "$root/openmoat.rb"; do
        [ "$waited" -lt "${CLEAN_INSTALL_WAIT_MINUTES:-0}" ] ||
            fail "the tap's formula is not at ${tag#v} (waited $waited minutes)"
        sleep 60
        waited=$((waited + 1))
    done
    echo "ok    the tap's formula is at ${tag#v}"
    installs=0
    for line in "${quickstart[@]}"; do
        case "$line" in
        "brew install "*)
            echo "\$ $line"
            (cd "$HOME" && bash -c "$line") </dev/null
            installs=$((installs + 1))
            ;;
        esac
    done
    [ "$installs" -gt 0 ] || fail "the README quick start has no brew install line"
    expected_bin="$(brew --prefix)/bin/openmoat"
    ;;
shell)
    curl --proto '=https' --tlsv1.2 -fLsS --retry 3 -o "$root/openmoat-installer.sh" \
        "$release_url/download/openmoat-installer.sh"
    curl --proto '=https' --tlsv1.2 -fLsS --retry 3 -o "$root/sha256.sum" \
        "$release_url/download/sha256.sum"
    want=$(grep -E '[ *]openmoat-installer\.sh$' "$root/sha256.sum" | cut -d' ' -f1)
    if command -v sha256sum >/dev/null; then
        got=$(sha256sum "$root/openmoat-installer.sh" | cut -d' ' -f1)
    else
        got=$(shasum -a 256 "$root/openmoat-installer.sh" | cut -d' ' -f1)
    fi
    if [ -z "$want" ] || [ "$got" != "$want" ]; then
        fail "openmoat-installer.sh sha256 $got is not the release's ${want:-<none>}"
    fi
    echo "ok    openmoat-installer.sh sha256 matches sha256.sum"
    if [ -n "${GH_TOKEN:-}" ]; then
        gh attestation verify "$root/openmoat-installer.sh" --repo crocodile-labs/openmoat
        echo "ok    openmoat-installer.sh has the release workflow's build attestation"
    else
        echo "skip  no GH_TOKEN: attestation not verified"
    fi
    # The token was for the attestation only: the installer, OpenMoat and the
    # agents run without it, as on a new user's machine.
    unset GH_TOKEN
    # What `curl … | sh` runs, from the file just checked.
    (cd "$HOME" && sh "$root/openmoat-installer.sh") </dev/null
    expected_bin="$HOME/.cargo/bin/openmoat"
    ;;
cargo)
    command -v cargo >/dev/null || fail "no cargo on PATH"
    export CARGO_HOME="$HOME/.cargo"
    throwaway_refuse
    (cd "$HOME" && cargo install openmoat --locked) </dev/null
    expected_bin="$CARGO_HOME/bin/openmoat"
    ;;
esac
export PATH="${expected_bin%/*}:$PATH"
found=$(command -v openmoat) || fail "openmoat is not on PATH after the install"
[ "$found" = "$expected_bin" ] || fail "openmoat on PATH is $found, not the installed $expected_bin"
openmoat --version | tee "$out/version.txt"
installed=$(head -1 "$out/version.txt")
case "$installed" in
*" ${tag#v}"*) echo "ok    $method installs the latest release, ${tag#v}" ;;
*)
    if [ "$method" = cargo ]; then
        # crates.io is published after a maintainer approves the release
        # environment, so a just-published release can lag here for a while.
        echo "::warning title=clean install (cargo)::crates.io has $installed, the latest release is $tag"
    else
        fail "$method installed $installed, not the latest release $tag"
    fi
    ;;
esac

# ---- the README quick start -------------------------------------------------

begin "snapshot before OpenMoat runs"
snapshot save "$HOME" "$root/home-before.json"

begin "README quick start"
ran=0
for line in "${quickstart[@]}"; do
    case "$line" in
    "brew install "*)
        [ "$method" = brew ] || echo "skip  $line (this job installs with $method)"
        continue
        ;;
    esac
    ran=$((ran + 1))
    echo "\$ $line"
    run_logged "quickstart-$ran" bash -c "cd \"\$HOME\" && $line"
    case "$line" in
    "openmoat init"*)
        [ "$rc" -eq 0 ] || fail "\`$line\` exited $rc"
        grep -qF '· agents           none found; pass --hosts to set one up' "$out/quickstart-$ran.txt" ||
            fail "\`$line\` with no agent installed does not say: none found; pass --hosts to set one up"
        echo "ok    with no agent installed, init says none was found"
        ;;
    "openmoat policy check"*)
        [ "$rc" -eq 2 ] || fail "\`$line\` exited $rc, not 2 (deny)"
        python3 -I "$repo/scripts/ci/readme-quickstart.py" compare "$out/expected-policy-check.txt" \
            "$out/quickstart-$ran.txt" "$HOME"
        ;;
    *) [ "$rc" -eq 0 ] || fail "\`$line\` exited $rc" ;;
    esac
done
[ "$ran" -gt 0 ] || fail "the README quick start ran no command"

begin "demo, status and doctor"
run_logged demo openmoat demo
[ "$rc" -eq 0 ] || fail "openmoat demo exited $rc"
grep -q 'cat ~/.ssh/id_rsa' "$out/demo.txt" || fail "openmoat demo does not show the key read"
run_logged status openmoat status
[ "$rc" -eq 0 ] || fail "openmoat status exited $rc right after the quick start"
run_logged doctor openmoat doctor
[ "$rc" -eq 0 ] || fail "openmoat doctor exited $rc right after the quick start"
snapshot compare "$HOME" "$root/home-before.json" --exclude .moat ||
    fail "the quick start changed a file outside ~/.moat with no agent installed"
echo "ok    with no agent installed, OpenMoat wrote only its own ~/.moat"

# ---- with Claude Code installed ---------------------------------------------

begin "install Claude Code"
claude_dir="$root/claude"
mkdir -p "$claude_dir"
claude_version=$(npm view @anthropic-ai/claude-code@latest version)
npm install --prefix "$claude_dir" --ignore-scripts --no-audit --no-fund --save-exact \
    "@anthropic-ai/claude-code@$claude_version" >"$out/claude-npm.txt" 2>&1 || {
    cat "$out/claude-npm.txt"
    fail "npm install @anthropic-ai/claude-code@$claude_version"
}
npm audit signatures --prefix "$claude_dir"
# The postinstall only links the platform package's binary over a stub; with
# lifecycle scripts off the binary is used where it is.
platform=$(node -p 'process.platform + "-" + process.arch')
claude_bin="$claude_dir/node_modules/@anthropic-ai/claude-code-$platform/claude"
[ -x "$claude_bin" ] || fail "no Claude Code binary at $claude_bin"
export PATH="${claude_bin%/*}:$PATH"
claude --version </dev/null

begin "init before Claude Code's first start"
run_logged init-unstarted openmoat init
[ "$rc" -eq 0 ] || fail "openmoat init exited $rc"
grep -qF '· agents           none found; pass --hosts to set one up' "$out/init-unstarted.txt" ||
    fail "init before Claude Code ever started does not say none was found"
echo "ok    an agent never started has no configuration directory; init says none was found"

begin "Claude Code's first start"
# A first start against a local fake API: no account, nothing leaves the machine.
python3 -I "$repo/tests/differential/fake_api.py" >"$root/fake-api.port" 2>"$out/fake-api.log" &
fake_pid=$!
tries=0
until [ -s "$root/fake-api.port" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ] || ! kill -0 "$fake_pid" 2>/dev/null; then
        fail "the fake API did not start"
    fi
    sleep 0.1
done
read -r fake_port <"$root/fake-api.port"
(cd "$HOME" && ANTHROPIC_API_KEY=sk-ant-moat-fake-key ANTHROPIC_BASE_URL="http://127.0.0.1:$fake_port" \
    HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    perl -e 'alarm 120; exec @ARGV or die "exec: $!\n"' claude -p "hello") </dev/null >"$out/claude-first-start.txt" 2>&1 || true
kill "$fake_pid" 2>/dev/null || true
wait "$fake_pid" 2>/dev/null || true
fake_pid=""
cat "$out/claude-first-start.txt"
[ -d "$HOME/.claude" ] || fail "Claude Code's first start did not create ~/.claude"

begin "snapshot before init"
snapshot save "$HOME" "$root/home-with-claude.json" --exclude .moat

begin "init without a terminal"
run_logged init-no-terminal openmoat init
[ "$rc" -eq 0 ] || fail "openmoat init exited $rc"
grep -qF 'found Claude Code; none changed without a terminal' "$out/init-no-terminal.txt" ||
    fail "init without a terminal does not say it found Claude Code and changed nothing"
snapshot compare "$HOME" "$root/home-with-claude.json" --exclude .moat ||
    fail "init without a terminal changed a file"
echo "ok    init without a terminal names Claude Code and changes no file"

begin "init --yes"
run_logged init-yes openmoat init --yes
[ "$rc" -eq 0 ] || fail "openmoat init --yes exited $rc"
openmoat status --format json >"$out/status.json" 2>"$out/status.err" || true
openmoat doctor --format json >"$out/doctor.json" 2>"$out/doctor.err" || true
python3 -I "$repo/scripts/ci/latest-agents/check.py" protected claude-code "$out/status.json" "$out/doctor.json"

begin "uninstall"
run_logged uninstall python3 -I "$repo/scripts/ci/pty-run.py" openmoat uninstall
[ "$rc" -eq 0 ] || fail "openmoat uninstall exited $rc"
snapshot compare "$HOME" "$root/home-with-claude.json" --exclude .moat ||
    fail "openmoat uninstall did not give every file back as it was"
[ -d "$HOME/.moat" ] || fail "openmoat uninstall deleted the state directory without --purge"
echo "ok    uninstall gave every file back byte for byte and kept the state directory"

begin "uninstall --purge"
run_logged uninstall-purge python3 -I "$repo/scripts/ci/pty-run.py" openmoat uninstall --purge
[ "$rc" -eq 0 ] || fail "openmoat uninstall --purge exited $rc"
[ ! -e "$HOME/.moat" ] || fail "openmoat uninstall --purge left $HOME/.moat"
snapshot compare "$HOME" "$root/home-with-claude.json" ||
    fail "after uninstall --purge the home is not as it was before OpenMoat's init"
echo "ok    nothing of OpenMoat's is left in the home"
step=done
echo "PASS  clean install ($method): $installed"
