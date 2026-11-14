# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# Cursor's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

install_agent() {
    local os arch build
    # Cursor publishes the CLI only through its install script, which names one
    # versioned package URL; the script is read as a file and only that URL is
    # taken from it. Cursor publishes no checksum, so the package's sha256 is
    # printed for the record.
    curl -fsSL --retry 3 -o "$root/cursor-install.sh" https://cursor.com/install
    build=$(grep -Eo 'downloads\.cursor\.com/lab/[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-f]+/' \
        "$root/cursor-install.sh" | head -1) || true
    build=${build#downloads.cursor.com/lab/}
    build=${build%/}
    [ -n "$build" ] || {
        echo "FAIL  no package URL in Cursor's install script" >&2
        return 1
    }
    case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; esac
    case "$(uname -m)" in x86_64 | amd64) arch=x64 ;; arm64 | aarch64) arch=arm64 ;; esac
    curl -fsSL --retry 3 -o "$root/cursor-agent.tar.gz" \
        "https://downloads.cursor.com/lab/$build/$os/$arch/agent-cli-package.tar.gz"
    echo "cursor-agent $build package sha256:"
    if command -v sha256sum >/dev/null; then sha256sum "$root/cursor-agent.tar.gz"; else shasum -a 256 "$root/cursor-agent.tar.gz"; fi
    mkdir -p "$agent_dir"
    tar -xzf "$root/cursor-agent.tar.gz" -C "$agent_dir"
    bin=$(find "$agent_dir" -name cursor-agent -type f -perm -u+x | head -1)
    [ -n "$bin" ] || {
        echo "FAIL  no cursor-agent in the package" >&2
        return 1
    }
}

load_hook() {
    # Every cursor-agent run needs a Cursor sign-in or API key, so nothing here
    # starts it; the hook file is checked as written and the payloads below.
    echo "skip  cursor-agent needs an account to run; not proven that it loads hooks.json"
}
