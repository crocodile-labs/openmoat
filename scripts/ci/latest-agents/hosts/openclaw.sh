# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# OpenClaw's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

prepare_agent() {
    # openclaw.json: the provider and the default model.
    port_file="$OPENCLAW_STATE_DIR/openclaw.json"
    printf '%s\n' '{"models":{"mode":"merge","providers":{"fake":{"baseUrl":"http://127.0.0.1:FAKE_PORT/v1","apiKey":"fake-key","api":"openai-completions","models":[{"id":"fake-model","name":"Fake","reasoning":false,"input":["text"],"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0},"contextWindow":120000,"maxTokens":8192}]}}},"agents":{"defaults":{"model":{"primary":"fake/fake-model"}}}}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call exec="{\"command\": \"$denied\"}"
}

# check_config_format <file> <format>: the agent's own judgement of a file.
check_config_format() {
    local file=$1
    # OpenClaw reads openclaw.json as JSON5; its own validator is the judge.
    "$bin" config validate --json </dev/null >"$out/openclaw-validate.json" \
        2>"$out/openclaw-validate.err" || true
    cat "$out/openclaw-validate.err"
    check openclaw-valid "$file" "$out/openclaw-validate.json"
}

load_hook() {
    "$bin" plugins inspect openmoat --runtime --json </dev/null >"$out/openclaw-inspect.json" 2>"$out/openclaw-inspect.err" || {
        cat "$out/openclaw-inspect.json" "$out/openclaw-inspect.err"
        exit 1
    }
    check openclaw-inspect "$out/openclaw-inspect.json"
    (cd "$project" && bounded 180 "$bin" agent exec --config "$OPENCLAW_STATE_DIR/openclaw.json" \
        --state-dir "$OPENCLAW_STATE_DIR" --model fake/fake-model --code-mode direct --timeout 120 \
        --json --cwd "$project" "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" --port "$pinned_port" \
        --call exec="{\"command\": \"$probe_cmd\"}"
    (cd "$project" && bounded "$limit" "$bin" agent exec --config "$OPENCLAW_STATE_DIR/openclaw.json" \
        --state-dir "$OPENCLAW_STATE_DIR" --model fake/fake-model --code-mode direct \
        --timeout "$limit" --json --cwd "$project" "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
