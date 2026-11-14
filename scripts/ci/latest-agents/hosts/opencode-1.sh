# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# OpenCode 1's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

prepare_agent() {
    # OpenCode 1's opencode.json: an OpenAI-compatible provider (its SDK is
    # bundled, so nothing is fetched) and that model as the default.
    port_file="$XDG_CONFIG_HOME/opencode/opencode.json"
    # shellcheck disable=SC2016 # `$schema` is OpenCode's JSON key, not a variable
    printf '%s\n' '{"$schema":"https://opencode.ai/config.json","provider":{"fake":{"npm":"@ai-sdk/openai-compatible","name":"Fake","options":{"baseURL":"http://127.0.0.1:FAKE_PORT/v1","apiKey":"fake-key"},"models":{"fake-model":{"name":"Fake","tool_call":true}}}},"model":"fake/fake-model"}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\", \"description\": \"probe\"}"
}

# OpenCode 1 says which plugin files it found (`debug info`) but not that their
# `server` ran; a headless `opencode run` against the fake API proves that.
load_hook() {
    (cd "$project" && bounded 60 "$bin" debug info) </dev/null >"$out/opencode-debug-info.txt" 2>&1 || true
    cat "$out/opencode-debug-info.txt"
    grep -q 'plugins/openmoat\.js' "$out/opencode-debug-info.txt" || {
        echo "FAIL  opencode debug info does not list plugins/openmoat.js"
        return 1
    }
    (cd "$project" && OPENCODE_DISABLE_MODELS_FETCH=1 \
        bounded 180 "$bin" run --print-logs --format json "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    if grep -q 'failed to load plugin' "$out/agent.txt"; then
        echo "FAIL  OpenCode failed to load a plugin"
        return 1
    fi
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" --port "$pinned_port" \
        --call bash="{\"command\": \"$probe_cmd\", \"description\": \"probe\"}"
    (cd "$project" && OPENCODE_DISABLE_MODELS_FETCH=1 \
        bounded "$limit" "$bin" run --print-logs --format json "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
