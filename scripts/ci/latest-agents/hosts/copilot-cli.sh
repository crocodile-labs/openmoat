# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# GitHub Copilot CLI's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

load_hook() {
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\", \"description\": \"probe\"}" \
        --then bash="{\"command\": \"$harmless\", \"description\": \"after-call capture\"}"
    # Copilot CLI's own provider (BYOK): no GitHub sign-in with a base URL set.
    (cd "$project" && COPILOT_OFFLINE=true COPILOT_PROVIDER_TYPE=openai \
        COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:$fake_port/v1" COPILOT_PROVIDER_API_KEY=fake-key \
        COPILOT_MODEL=fake-model bounded 180 "$bin" -p "run it" --allow-all-tools) \
        </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$probe_cmd\", \"description\": \"probe\"}"
    (cd "$project" && COPILOT_OFFLINE=true COPILOT_PROVIDER_TYPE=openai \
        COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:$fake_port/v1" COPILOT_PROVIDER_API_KEY=fake-key \
        COPILOT_MODEL=fake-model bounded "$limit" "$bin" -p "run it" --allow-all-tools) \
        </dev/null >"$log-agent.txt" 2>&1 || true
}
