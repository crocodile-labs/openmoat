# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Qwen Code's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

load_hook() {
    # Qwen Code is a preview host: no model turn is driven through a real
    # `qwen` yet (its provider settings for a fake API were not checked), so the
    # hook file is checked as written and the payloads below.
    echo "skip  no model turn is driven through qwen yet; not proven that it runs the hook"
}
