# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# The Cline CLI's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

load_hook() {
    # Cline lists the hook files it found; then one headless run against the
    # fake API (its `openai-compatible` provider) must have its
    # `run_commands` call cancelled by OpenMoat's script.
    "$bin" config hooks --json </dev/null >"$out/cline-hooks.json" 2>&1 || true
    cat "$out/cline-hooks.json"
    grep -q "$CLINE_DIR/hooks/PreToolUse" "$out/cline-hooks.json" || {
        echo "FAIL  cline config hooks does not list OpenMoat's PreToolUse"
        exit 1
    }
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call run_commands="{\"commands\": [\"$denied\"]}"
    "$bin" auth -p openai-compatible -k fake-key -m fake-model \
        -b "http://127.0.0.1:$fake_port/v1" </dev/null >"$out/cline-auth.txt" 2>&1 || {
        cat "$out/cline-auth.txt"
        exit 1
    }
    (cd "$project" && bounded 180 "$bin" --json "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" \
        --call run_commands="{\"commands\": [\"$probe_cmd\"]}"
    "$bin" auth -p openai-compatible -k fake-key -m fake-model \
        -b "http://127.0.0.1:$fake_port/v1" </dev/null >"$log-auth.txt" 2>&1 || true
    (cd "$project" && bounded "$limit" "$bin" --json "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
