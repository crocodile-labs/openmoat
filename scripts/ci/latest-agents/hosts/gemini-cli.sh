# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Gemini CLI's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

load_hook() {
    # Gemini CLI's own test double for the model (`--fake-responses`): the
    # first turn calls run_shell_command, the second makes the harmless call
    # for the after-call capture, the third ends the session. A folder Gemini
    # CLI does not trust runs no settings hooks at all, so the project is
    # trusted for this run (`--skip-trust`).
    printf '%s\n' \
        "{\"method\":\"generateContentStream\",\"response\":[{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"run_shell_command\",\"args\":{\"command\":\"$denied\",\"description\":\"probe\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]}]}" \
        "{\"method\":\"generateContentStream\",\"response\":[{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"run_shell_command\",\"args\":{\"command\":\"$harmless\",\"description\":\"after-call capture\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]}]}" \
        '{"method":"generateContentStream","response":[{"candidates":[{"content":{"role":"model","parts":[{"text":"done"}]},"finishReason":"STOP","index":0}]}]}' \
        >"$root/gemini-responses.jsonl"
    # A named model: with the default (`auto`) Gemini CLI first asks the model
    # which model to route to (`generateContent`), a call the file does not hold.
    (cd "$project" && GEMINI_API_KEY=fake-key \
        bounded 180 "$bin" --skip-trust --approval-mode=yolo --model gemini-2.5-flash \
        --fake-responses "$root/gemini-responses.jsonl" -p "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    printf '%s\n' \
        "{\"method\":\"generateContentStream\",\"response\":[{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"run_shell_command\",\"args\":{\"command\":\"$probe_cmd\",\"description\":\"probe\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]}]}" \
        '{"method":"generateContentStream","response":[{"candidates":[{"content":{"role":"model","parts":[{"text":"done"}]},"finishReason":"STOP","index":0}]}]}' \
        >"$log-responses.jsonl"
    (cd "$project" && GEMINI_API_KEY=fake-key \
        bounded "$limit" "$bin" --skip-trust --approval-mode=yolo --model gemini-2.5-flash \
        --fake-responses "$log-responses.jsonl" -p "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
