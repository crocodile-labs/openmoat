# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# OpenCode 2's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

# OpenCode 2's plugin API reports each plugin's state, `active` only once its
# `setup` ran, asked of one `opencode serve` until the location's plugins have
# activated; its headless run is not driven here (its provider settings
# differ from 1's and are not read yet).
load_hook() {
    # One long-lived `opencode serve`, polled. `api --standalone` starts a
    # new server per call, and a new location activates its plugins in the
    # background, so its single answer is `[]` before activation applies
    # (v2.2.0 `core/src/plugin.ts:44,51-53`, `plugin/supervisor.ts`). A
    # location stays loaded once built (`core/src/location-services.ts`,
    # `idleTimeToLive: infinity`), so a later request sees the settled set.
    local pw url tries=0 rc=0 serve_pid
    pw="moat-ci-$RANDOM$RANDOM$RANDOM"
    (cd "$project" && OPENCODE_PASSWORD="$pw" exec perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' \
        300 "$bin" serve --hostname 127.0.0.1 --port 0) </dev/null >"$out/opencode-serve.txt" \
        2>"$out/opencode-serve.err" &
    serve_pid=$!
    url=""
    while [ -z "$url" ]; do
        url=$(grep -o 'server listening on http://[^ ]*' "$out/opencode-serve.txt" 2>/dev/null | head -n 1) || true
        url=${url#server listening on }
        [ -n "$url" ] && break
        tries=$((tries + 1))
        if [ "$tries" -gt 120 ] || ! kill -0 "$serve_pid" 2>/dev/null; then
            cat "$out/opencode-serve.txt" "$out/opencode-serve.err"
            kill "$serve_pid" 2>/dev/null || true
            echo "FAIL  opencode serve did not report its address"
            return 1
        fi
        sleep 0.5
    done
    echo "ok    opencode serve listening on $url"
    tries=0
    while :; do
        curl -sS --max-time 10 -u "opencode:$pw" \
            "$url/api/plugin?location%5Bdirectory%5D=$project" \
            >"$out/opencode-plugins.json" 2>"$out/opencode-plugins.err" || true
        check opencode-settled "$out/opencode-plugins.json" && break
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ] || ! kill -0 "$serve_pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    cat "$out/opencode-plugins.json" "$out/opencode-plugins.err"
    check opencode-active "$out/opencode-plugins.json" || rc=$?
    kill "$serve_pid" 2>/dev/null || true
    wait "$serve_pid" 2>/dev/null || true
    cat "$out/opencode-serve.err"
    return "$rc"
}
