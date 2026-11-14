# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Hermes Agent's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

install_agent() {
    local location tag
    # The latest release, from the redirect of the releases page (no API token).
    location=$(curl -fsSI --retry 3 https://github.com/NousResearch/hermes-agent/releases/latest |
        tr -d '\r' | grep -i '^location:') || true
    tag=${location##*/tag/}
    case "$tag" in
    v[0-9]*.[0-9]*) ;;
    *)
        echo "FAIL  no Hermes Agent release tag in: $location" >&2
        return 1
        ;;
    esac
    echo "hermes: release $tag"
    # The installer of that tag, downloaded and read as a file, never piped.
    curl -fsSL --retry 3 -o "$root/hermes-install.sh" \
        "https://raw.githubusercontent.com/NousResearch/hermes-agent/$tag/scripts/install.sh"
    bash "$root/hermes-install.sh" --non-interactive --skip-browser --skip-computer-use \
        --hermes-home "$HERMES_HOME" >"$out/hermes-install.log" 2>&1 </dev/null || {
        tail -50 "$out/hermes-install.log"
        return 1
    }
    bin="$HERMES_HOME/hermes-agent/.hermes/bin/hermes"
    release_tag=$tag
}

# check_config_format <file> <format>: the agent's own judgement of a file.
check_config_format() {
    local file=$1
    # Hermes reads its own config.yaml: the hook must be listed and allowlisted.
    "$bin" hooks list </dev/null >"$out/hermes-hooks-list.txt" 2>&1
    cat "$out/hermes-hooks-list.txt"
    grep -q 'openmoat.*guard.*✓ allowed' "$out/hermes-hooks-list.txt" || {
        echo "FAIL  hermes hooks list does not show OpenMoat's hook allowed"
        exit 1
    }
    echo "ok    hermes parses $file and lists OpenMoat's hook, allowlisted"
}

load_hook() {
    # Hermes's own hook commands: `doctor` runs the allowlisted hook on a
    # synthetic payload, `test` fires it through the code a session uses.
    "$bin" hooks doctor </dev/null >"$out/hermes-hooks-doctor.txt" 2>&1 || true
    cat "$out/hermes-hooks-doctor.txt"
    grep -q 'All shell hooks look healthy' "$out/hermes-hooks-doctor.txt" || {
        echo "FAIL  hermes hooks doctor does not call OpenMoat's hook healthy"
        exit 1
    }
    printf '{"args": {"command": "%s"}}\n' "$denied" >"$root/hermes-deny.json"
    (cd "$project" && "$bin" hooks test pre_tool_call --for-tool terminal \
        --payload-file "$root/hermes-deny.json") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    grep -q 'parsed (Hermes wire shape): .*"block".*secrets-paths' "$out/agent.txt" || {
        echo "FAIL  hermes hooks test did not get OpenMoat's block"
        exit 1
    }
    expect_denied "$out/agent.txt"
}
