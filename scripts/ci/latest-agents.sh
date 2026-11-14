#!/usr/bin/env bash
# The weekly latest-agent check for one agent (.github/workflows/latest-agents.yml;
# what each agent's run proves and cannot: scripts/ci/latest-agents/README.md).
#
#   OPENMOAT_BIN=/abs/path/openmoat scripts/ci/latest-agents.sh <agent>
#
# <agent> is an entry of scripts/ci/latest-agents/agents.json, which is written
# from the host specs (each host's `weekly`); what differs between agents as
# data is read from it, and the steps no fact can say are the functions of the
# record's own script, scripts/ci/latest-agents/hosts/<agent>.sh (`script`).
# In a new temporary directory, with HOME, MOAT_HOME and every agent's
# configuration directory inside it (refused otherwise, before every step that
# writes), it:
#
#   1. installs the agent's latest release, with npm's lifecycle scripts off
#      and the registry signatures verified (`npm audit signatures`), or by the
#      script's `install_agent`;
#   2. prints its version and the one the adapter was checked against; a newer
#      one is reported, not failed;
#   3. runs `openmoat init --hosts <host> --yes` (after the script's
#      `prepare_agent`), then requires `openmoat status` and `openmoat doctor`
#      to call the agent protected by its hook, doctor to be healthy, and the
#      agent's configuration files to still parse;
#   4. where the agent can without an account, starts the real agent so it
#      loads OpenMoat's hook or plugin and makes one call, `cat ~/.ssh/id_rsa`,
#      against a local fake model API (or the agent's own hook test command),
#      and requires the audit log to hold that call denied by secrets-paths and
#      the fake key never to appear in what the agent printed (the script's
#      `load_hook`);
#   5. sends one allowed (`git status`) and one denied (`cat ~/.ssh/id_rsa`)
#      payload, in the agent's own format (its golden fixture), through
#      `openmoat guard`, and checks the reply;
#   6. records what the agent's after-call event sends, where it runs with no
#      account (after_call.py): reported in the job's annotations, never failed;
#   7. where the record proves `hook-failure`, makes OpenMoat's hook fail in the
#      ways its guard cannot catch itself (the binary exits 1 with nothing
#      printed, or is gone; a hang is not tried, see hook_fails), has the agent
#      read a probe file each time (the script's `probe_agent`), and compares
#      what the agent did with the host fact `openmoat status --format json`
#      reports (`hook_failure`, ADR-079): a call that ran where the fact says
#      the agent blocks fails the job; a call blocked where it says the agent
#      runs it, or no evidence either way, is reported. hook-failure.json in
#      the output holds every outcome.
#
# No account, key or secret is used; the fake API listens on loopback only.
# With LATEST_AGENTS_OUT set, result.json (agent, version, checked version,
# outcome, failed step) and every log are written there for the workflow.
# Never run it on a machine whose agents you use: it is meant for a CI runner,
# and although nothing leaves the temporary directory, the agents it installs
# are unreviewed releases.
set -euo pipefail

agent=${1:?usage: latest-agents.sh <agent of scripts/ci/latest-agents/agents.json>}
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
lib="$repo/scripts/ci/latest-agents"
moat=${OPENMOAT_BIN:?OPENMOAT_BIN must name the openmoat binary to test}
case "$moat" in
/*) ;;
*)
    echo "latest-agents: OPENMOAT_BIN must be an absolute path" >&2
    exit 64
    ;;
esac
[ -x "$moat" ] || {
    echo "latest-agents: $moat is not executable" >&2
    exit 64
}

check() {
    python3 -I "$lib/check.py" "$@"
}
host=$(check get "$agent" host) || {
    echo "latest-agents: no agent $agent in agents.json" >&2
    exit 64
}
name=$(check get "$agent" name)
install=$(check get "$agent" install)
script="$repo/$(check get "$agent" script)"
[ -f "$script" ] || {
    echo "latest-agents: no script $script for $agent" >&2
    exit 64
}

# shellcheck disable=SC1091 # the library is linted as a file of its own
. "$repo/scripts/ci/lib/throwaway.sh"
root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/latest-$agent.XXXXXX")
out=${LATEST_AGENTS_OUT:-$root/out}
mkdir -p "$out"
step=setup
version=""
relation=""
checked=$(check get "$agent" checked.version || echo none)
fake_pid=""
fake_log=""
finish() {
    local rc=$?
    [ -z "$fake_pid" ] || kill "$fake_pid" 2>/dev/null || true
    # The one directory outside the throwaway root (Claude Code's tool shell).
    case "${tool_shell_tmp:-}" in /tmp/moat-ci-tool-shell.*) rm -rf "$tool_shell_tmp" ;; esac
    # The fake API's log is in the artefact too; the job log shows it at once.
    [ "$rc" -eq 0 ] || show_fake
    # Also on a failed run: what arrived before it is what a reader needs.
    [ -z "${after_call_dir:-}" ] ||
        python3 -I "$lib/after_call.py" report "$agent" "$after_call_dir" "${fake_log:--}" "$step" || true
    local outcome=passed
    [ "$rc" -eq 0 ] || outcome=failed
    printf '{"agent":"%s","host":"%s","name":"%s","os":"%s","version":"%s","checked":"%s","relation":"%s","outcome":"%s","step":"%s"}\n' \
        "$agent" "$host" "$name" "${RUNNER_OS:-$(uname -s)}" "$version" "$checked" "$relation" \
        "$outcome" "$step" >"$out/result.json"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### $name ($agent) on ${RUNNER_OS:-$(uname -s)}: $outcome"
            echo
            echo "| installed | checked against | |"
            echo "|---|---|---|"
            echo "| ${version:-?} | $checked | ${relation:-} |"
            if [ "$rc" -ne 0 ]; then
                echo
                echo "Failed in step \`$step\`; the logs are in the \`latest-agent-$agent-*\` artefact."
            fi
            if [ -f "$out/background-mcp.txt" ]; then
                echo
                cat "$out/background-mcp.txt"
            fi
        } >>"$GITHUB_STEP_SUMMARY"
    fi
    if [ "$rc" -eq 0 ]; then
        echo "PASS  $name ($agent) $version"
    else
        echo "FAIL  $name ($agent) in step $step"
    fi
    exit "$rc"
}
trap finish EXIT
throwaway_setup "$root"
export MOAT_HOME="$HOME/.moat"
# Every agent's directory inside the throwaway home, whichever agent runs
# (agents.json's `_env`, from the host specs).
variables=$(check env)
while IFS=$'\t' read -r variable value; do
    value=${value//\{HOME\}/$HOME}
    export "$variable=${value//\{ROOT\}/$root}"
done <<<"$variables"
# No agent may update itself or report home in the middle of the check.
export DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 COPILOT_AUTO_UPDATE=false
export PI_OFFLINE=1 PI_TELEMETRY=0 GEMINI_FORCE_FILE_STORAGE=true OPENCODE_DISABLE_AUTOUPDATE=1
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
project="$HOME/project"
mkdir -p "$project" "$HOME/.ssh"
# Only this agent's directory, as its first start makes it: OpenMoat finds an
# agent by its directory, and doctor reports one it finds without the hook.
first_dir=$(check dir "$agent")
[ -z "$first_dir" ] || mkdir -p "$first_dir"
throwaway_refuse

# A fake key whose text must never reach an agent's output.
marker="OPENMOAT-FAKE-KEY-$RANDOM$RANDOM"
printf '%s\n' "$marker" >"$HOME/.ssh/id_rsa"
chmod 600 "$HOME/.ssh/id_rsa"
git -C "$project" init -q
denied='cat ~/.ssh/id_rsa'
# Runs after the denied call, so the after-call event has a call that ran.
harmless='echo moat-ci-after-call-output'


begin() {
    step=$1
    echo "== $step"
    throwaway_refuse
}

# start_fake <log> <command...>: a fake model API in the background; sets
# fake_port from the first line it prints once it listens.
start_fake() {
    local log=$1
    shift
    "$@" >"$log.port" 2>"$log" &
    fake_pid=$!
    local tries=0
    until [ -s "$log.port" ]; do
        tries=$((tries + 1))
        if [ "$tries" -gt 100 ] || ! kill -0 "$fake_pid" 2>/dev/null; then
            cat "$log" >&2
            echo "FAIL  the fake model API did not start" >&2
            return 1
        fi
        sleep 0.1
    done
    read -r fake_port <"$log.port"
    fake_log=$log
    # It answers before any agent is pointed at it.
    curl -fsS -m 10 -o /dev/null "http://127.0.0.1:$fake_port/v1/models" || {
        cat "$log" >&2
        echo "FAIL  the fake model API listens on $fake_port but does not answer" >&2
        return 1
    }
}

# show_fake: every request the fake model API saw, for a failed real-agent step.
show_fake() {
    [ -z "${fake_log:-}" ] || [ ! -f "$fake_log" ] || {
        echo "-- requests the fake model API saw ($fake_log):"
        cat "$fake_log"
    }
}

stop_fake() {
    [ -z "$fake_pid" ] || kill "$fake_pid" 2>/dev/null || true
    wait "$fake_pid" 2>/dev/null || true
    fake_pid=""
}

# bounded <seconds> <command...>: run with a hard time limit (perl is on every
# runner; coreutils `timeout` is not on macOS).
bounded() {
    local seconds=$1
    shift
    perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$seconds" "$@"
}

audit() {
    "$moat" show --since all --format json >"$1" 2>"$1.err" || : >"$1"
}

# expect_denied <log...>: the real agent's call reached OpenMoat and was denied,
# and the fake key is in none of the logs.
expect_denied() {
    local markers=() log
    audit "$out/audit-after.json"
    for log in "$@"; do
        markers+=("$log=$marker")
    done
    check denied "$host" "$out/audit-before.json" "$out/audit-after.json" "${markers[@]}"
}

# The record's own steps: `canary`, or `load_hook` and what else its record
# needs (`install_agent`, `prepare_agent`, `check_config_format`,
# `probe_agent`; crates/openmoat-hosts/tests/docs/weekly.rs checks which).
# shellcheck source=/dev/null # each script is linted as a file of its own
. "$script"

# ---- install --------------------------------------------------------------

agent_dir="$root/agent"
bin=""

install_npm() {
    local package latest platform binary
    package=$(check get "$agent" package)
    latest=$(npm view "$package@latest" version)
    echo "npm: $package@$latest"
    mkdir -p "$agent_dir"
    npm install --prefix "$agent_dir" --ignore-scripts --no-audit --no-fund --save-exact \
        "$package@$latest" >"$out/npm-install.log" 2>&1 || {
        cat "$out/npm-install.log"
        return 1
    }
    # Every package's registry signature and, where it has one, its provenance.
    npm audit signatures --prefix "$agent_dir" | tee "$out/npm-signatures.log"
    platform=$(node -p 'process.platform + "-" + process.arch')
    binary=$(check get "$agent" binary)
    bin="$agent_dir/${binary//\{platform\}/$platform}"
    npm_version=$latest
}

# A package only read, never installed: the script's canary is the whole run.
if [ "$install" = npm-pack ]; then
    canary
    exit 0
fi

begin install
# An install of the record's own sets `bin`, and `release_tag` (`v<version>`)
# where it knows the release.
case "$install" in
npm) install_npm ;;
*) install_agent ;;
esac
[ -x "$bin" ] || {
    echo "FAIL  $bin is not executable" >&2
    exit 1
}
export PATH="${bin%/*}:$agent_dir/node_modules/.bin:$PATH"

begin version
# OpenClaw replays its own install scripts on the first start (its package
# ships `.openclaw-lifecycle-pending`), so this is also that start.
bounded 300 "$bin" --version </dev/null >"$out/version.txt" 2>&1 || {
    cat "$out/version.txt"
    exit 1
}
cat "$out/version.txt"
compared=$(check version "$agent" "$(head -5 "$out/version.txt")")
version=${compared%%$'\t'*}
relation=${compared#*$'\t'}
if [ -n "${npm_version:-}" ] && [ "$version" != "$npm_version" ]; then
    echo "FAIL  the binary reports $version, npm installed $npm_version"
    exit 1
fi
if [ -n "${release_tag:-}" ] && [ "v$version" != "$release_tag" ]; then
    echo "FAIL  $name reports $version, the release is $release_tag"
    exit 1
fi
echo "ok    $name $version; $relation"

# ---- per-agent preparation, before init pins the files ---------------------

begin prepare
# A provider at the fake API goes in the agent's own file before init, which
# keeps the file's other keys and then pins it, so the API starts here and its
# port is written in now; a file init pinned cannot change after it. The
# script's `prepare_agent` writes `<port_file>.in` with FAKE_PORT in it.
port_file=""
if declare -F prepare_agent >/dev/null; then
    prepare_agent
fi
if [ -n "$port_file" ]; then
    template=$(<"$port_file.in")
    printf '%s\n' "${template//FAKE_PORT/$fake_port}" >"$port_file"
    rm -f "$port_file.in"
fi
# The recording hook goes beside OpenMoat's, and likewise before init pins the
# file. A capture never fails the job; only the agents after_call.py names get one.
after_call_dir="$out/after-call"
python3 -I "$lib/after_call.py" install "$agent" "$after_call_dir" "$root" "$HOME" "$project" || true

begin init
# The hook names the binary init runs from: a copy in the throwaway root, so
# the hook-failure step can make that one fail without touching OPENMOAT_BIN.
mkdir -p "$root/openmoat-bin"
cp "$moat" "$root/openmoat-bin/openmoat"
moat="$root/openmoat-bin/openmoat"
(cd "$HOME" && "$moat" init --hosts "$host" --yes) </dev/null >"$out/init.txt" 2>&1 || {
    cat "$out/init.txt"
    exit 1
}
cat "$out/init.txt"

begin "status and doctor"
"$moat" status --format json >"$out/status.json" 2>"$out/status.err" || true
"$moat" doctor >"$out/doctor.txt" 2>&1 || true
"$moat" doctor --format json >"$out/doctor.json" 2>"$out/doctor.err" || true
cat "$out/doctor.txt"
check protected "$agent" "$out/status.json" "$out/doctor.json"

begin "config files parse"
configs=$(check configs "$agent")
while IFS=$'\t' read -r file format; do
    [ -f "$file" ] || {
        echo "FAIL  $file is missing after init"
        exit 1
    }
    case "$format" in
    json) check json "$file" ;;
    javascript)
        node --check "$file"
        echo "ok    $file parses as JavaScript"
        ;;
    shell)
        sh -n "$file"
        echo "ok    $file parses as a POSIX shell script"
        ;;
    # A format of the agent's own: the script asks the agent.
    *)
        if declare -F check_config_format >/dev/null; then
            check_config_format "$file" "$format"
        else
            echo "latest-agents: unknown config format $format" >&2
            exit 64
        fi
        ;;
    esac
done <<<"$configs"

# ---- the real agent loads OpenMoat's hook ----------------------------------

begin "real agent loads the hook"
audit "$out/audit-before.json"
# A capture build (`--features capture-payloads`, the workflow's) copies every
# payload the real agent sends `openmoat guard` here; a release build ignores
# the variable. Only this step: the payloads below are OpenMoat's own fixtures.
mkdir -p "$out/captured"
export OPENMOAT_CAPTURE_DIR="$out/captured"
load_hook
stop_fake
unset OPENMOAT_CAPTURE_DIR
check scrub "$host" "$version" "$out/captured" "$root" "$HOME" "$project" "$out/captured/scrubbed"

# ---- payloads in the agent's own format ------------------------------------

begin "guard payloads"
for which in allow deny; do
    check payload "$agent" "$which" "$HOME" "$project" >"$out/payload-$which.json"
    rc=0
    (cd "$project" && "$moat" guard --host "$host") <"$out/payload-$which.json" \
        >"$out/reply-$which.json" 2>"$out/reply-$which.err" || rc=$?
    check reply "$agent" "$which" "$rc" "$out/reply-$which.json"
done

# ---- the real agent when OpenMoat's hook fails (ADR-079) -------------------

# What the agent is asked to run while the hook fails: a read of a file with a
# marker of its own, copied into the project where the agent may write. The
# marker in what the agent printed or sent the fake API, or the copy, means the
# call ran.
probe_marker="OPENMOAT-HOOK-FAILURE-PROBE-$RANDOM$RANDOM"
printf '%s\n' "$probe_marker" >"$HOME/hook-failure-probe.txt"
probe_cmd="cat ~/hook-failure-probe.txt | tee hook-failure-ran.txt"
probe_ran="$project/hook-failure-ran.txt"

# hook_fails <mode>: the hook binary made to fail as <mode> says, the agent
# probed (the script's `probe_agent <log prefix> <seconds>`: the agent, with
# the hook as it is now, asked once to run the probe; as step 4 starts it,
# without its checks), the outcome compared with the host fact, the binary
# put back.
#   crash    exits 1 with nothing printed (a crash the guard cannot catch);
#   missing  is gone (an upgrade or uninstall removed it).
# A hook that hangs is not tried here: waiting out an agent's time limit
# (30 s to 600 s) under every agent would outlast the job's own time limit.
hook_fails() {
    local mode=$1 fact limit=180
    local calls="$out/hook-failure-$mode-calls.log"
    begin "hook fails: $mode"
    # A hook that cannot start is its own fact: a host may block only that.
    case "$mode" in
    missing) fact=$(check hook-failure-fact "$host" "$out/status.json" cannot_start) ;;
    *) fact=$(check hook-failure-fact "$host" "$out/status.json" fails) ;;
    esac
    mv "$moat" "$moat.real"
    : >"$calls"
    # shellcheck disable=SC2016 # `$$` and `$*` are the stand-in's own, at run time
    case "$mode" in
    crash) printf '#!/bin/sh\necho "$$ $*" >>"%s"\nexit 1\n' "$calls" >"$moat" ;;
    missing) ;;
    esac
    [ ! -f "$moat" ] || chmod +x "$moat"
    rm -f "$probe_ran"
    probe_agent "$out/hook-failure-$mode" "$limit"
    stop_fake
    rm -f "$moat"
    mv "$moat.real" "$moat"
    cat "$out/hook-failure-$mode-agent.txt"
    check hook-failure "$agent" "$mode" "$fact" "$probe_marker" "$probe_ran" "$calls" \
        "$out/hook-failure-$mode-agent.txt" "$out/hook-failure-$mode-api.log" \
        "$out/hook-failure.json"
}

: >"$out/hook-failure.json"
if check proves "$agent" hook-failure; then
    pinned_port=${fake_port:-0}
    for mode in crash missing; do
        hook_fails "$mode"
    done
else
    # Step 4 drives no model call through this agent (its record's `why`).
    check hook-failure-skip "$agent" all - "no model call is driven through this agent here" \
        "$out/hook-failure.json"
fi
step="done"
