# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# pi's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

prepare_agent() {
    # pi's models.json; pi has no other model.
    port_file="$PI_CODING_AGENT_DIR/models.json"
    printf '%s\n' '{"providers":{"fake":{"baseUrl":"http://127.0.0.1:FAKE_PORT/v1","api":"openai-completions","apiKey":"fake-key","models":[{"id":"fake-model"}]}}}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\"}"
}

load_hook() {
    (cd "$project" && bounded 180 "$bin" --provider fake --model fake-model --no-session --mode json \
        "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    grep -q '"isError":true' "$out/agent.txt" || {
        echo "FAIL  pi did not report the bash call as blocked"
        exit 1
    }
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    # The port step 4 wrote into pi's pinned models.json.
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" --port "$pinned_port" \
        --call bash="{\"command\": \"$probe_cmd\"}"
    (cd "$project" && bounded "$limit" "$bin" --provider fake --model fake-model --no-session \
        --mode json "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
