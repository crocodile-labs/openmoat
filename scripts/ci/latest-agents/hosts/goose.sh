# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # latest-agents.sh sources this file: its variables
# goose's own steps in the weekly latest-agent check
# (scripts/ci/latest-agents.sh sources this file; the record is in agents.json,
# written from the host's spec).

install_agent() {
    local location tag os arch asset
    # The latest release, from the redirect of the releases page (no API token);
    # the repository moved from block/goose, whose pages redirect here.
    location=$(curl -fsSI --retry 3 https://github.com/aaif-goose/goose/releases/latest |
        tr -d '\r' | grep -i '^location:') || true
    tag=${location##*/tag/}
    case "$tag" in
    v[0-9]*.[0-9]*) ;;
    *)
        echo "FAIL  no goose release tag in: $location" >&2
        return 1
        ;;
    esac
    case "$(uname -s)" in Linux) os=unknown-linux-gnu ;; Darwin) os=apple-darwin ;; esac
    case "$(uname -m)" in x86_64 | amd64) arch=x86_64 ;; arm64 | aarch64) arch=aarch64 ;; esac
    asset="goose-$arch-$os.tar.gz"
    echo "goose: release $tag, $asset"
    # goose publishes no checksum file, so the archive's sha256 is printed for the record.
    curl -fsSL --retry 3 -o "$root/$asset" \
        "https://github.com/aaif-goose/goose/releases/download/$tag/$asset"
    if command -v sha256sum >/dev/null; then sha256sum "$root/$asset"; else shasum -a 256 "$root/$asset"; fi
    mkdir -p "$agent_dir"
    tar -xzf "$root/$asset" -C "$agent_dir"
    bin=$(find "$agent_dir" -name goose -type f -perm -u+x | head -1)
    [ -n "$bin" ] || {
        echo "FAIL  no goose binary in $asset" >&2
        return 1
    }
    release_tag=$tag
}

load_hook() {
    # goose's OpenAI provider pointed at the fake API, set through the
    # environment (goose reads its settings from variables of the same name),
    # in `auto` mode so its own approval does not wait for a person; the
    # keyring is off so no secret store is touched. goose loads the plugin
    # `openmoat init` wrote when it starts.
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call shell="{\"command\": \"$denied\"}"
    (cd "$project" && GOOSE_PROVIDER=openai GOOSE_MODEL=fake-model GOOSE_MODE=auto \
        GOOSE_DISABLE_KEYRING=1 OPENAI_API_KEY=fake-key OPENAI_HOST="http://127.0.0.1:$fake_port" \
        OPENAI_BASE_PATH=v1/chat/completions \
        bounded 180 "$bin" run --no-session -t "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
}

# probe_agent <log prefix> <seconds>: the agent, with the hook as it is now,
# asked once to run the probe; as load_hook starts it, without its checks.
probe_agent() {
    local log=$1 limit=$2
    start_fake "$log-api.log" python3 -I "$lib/fake_openai.py" \
        --call shell="{\"command\": \"$probe_cmd\"}"
    (cd "$project" && GOOSE_PROVIDER=openai GOOSE_MODEL=fake-model GOOSE_MODE=auto \
        GOOSE_DISABLE_KEYRING=1 OPENAI_API_KEY=fake-key OPENAI_HOST="http://127.0.0.1:$fake_port" \
        OPENAI_BASE_PATH=v1/chat/completions \
        bounded "$limit" "$bin" run --no-session -t "run it") </dev/null >"$log-agent.txt" 2>&1 || true
}
