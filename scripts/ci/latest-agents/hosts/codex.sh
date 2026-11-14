# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Codex's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

load_hook() {
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call exec_command="{\"cmd\": \"$denied\"}" \
        --call shell_command="{\"command\": \"$denied\"}" \
        --call shell="{\"command\": [\"bash\", \"-lc\", \"$denied\"]}" \
        --then exec_command="{\"cmd\": \"$harmless\"}" \
        --then shell_command="{\"command\": \"$harmless\"}" \
        --then shell="{\"command\": [\"bash\", \"-lc\", \"$harmless\"]}"
    # The hook is run without Codex's persisted trust (`/hooks` is interactive):
    # what Codex's own exec tests do. A custom provider has no login and no
    # websocket; it is given on the command line, since init pinned config.toml.
    (cd "$project" && FAKE_OPENAI_KEY=fake-key \
        bounded 180 "$bin" exec --skip-git-repo-check --dangerously-bypass-hook-trust \
        -c 'model_provider="fake"' -c 'model="fake-model"' \
        -c "model_providers.fake={name=\"fake\",base_url=\"http://127.0.0.1:$fake_port/v1\",wire_api=\"responses\",env_key=\"FAKE_OPENAI_KEY\",request_max_retries=0,stream_max_retries=0}" \
        -o "$out/codex-last.txt" "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    touch "$out/codex-last.txt"
    expect_denied "$out/agent.txt" "$out/codex-last.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" \
        --call exec_command="{\"cmd\": \"$probe_cmd\"}" \
        --call shell_command="{\"command\": \"$probe_cmd\"}" \
        --call shell="{\"command\": [\"bash\", \"-lc\", \"$probe_cmd\"]}"
    (cd "$project" && FAKE_OPENAI_KEY=fake-key \
        bounded "$limit" "$bin" exec --skip-git-repo-check --dangerously-bypass-hook-trust \
        -c 'model_provider="fake"' -c 'model="fake-model"' \
        -c "model_providers.fake={name=\"fake\",base_url=\"http://127.0.0.1:$fake_port/v1\",wire_api=\"responses\",env_key=\"FAKE_OPENAI_KEY\",request_max_retries=0,stream_max_retries=0}" \
        "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
