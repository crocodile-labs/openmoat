#!/usr/bin/env bash
# The weekly latest-agent check for one agent (.github/workflows/latest-agents.yml;
# what each agent's run proves and cannot: scripts/ci/latest-agents/README.md).
#
#   OPENMOAT_BIN=/abs/path/openmoat scripts/ci/latest-agents.sh <agent>
#
# <agent> is an entry of scripts/ci/latest-agents/agents.json. In a new
# temporary directory, with HOME, MOAT_HOME and every agent's configuration
# directory inside it (refused otherwise, before every step that writes), it:
#
#   1. installs the agent's latest release, with npm's lifecycle scripts off
#      and the registry signatures verified (`npm audit signatures`);
#   2. prints its version and the one the adapter was checked against; a newer
#      one is reported, not failed;
#   3. runs `openmoat init --hosts <host> --yes`, then requires `openmoat status`
#      and `openmoat doctor` to call the agent protected by its hook, doctor to
#      be healthy, and the agent's configuration files to still parse;
#   4. where the agent can without an account, starts the real agent so it
#      loads OpenMoat's hook or plugin and makes one call, `cat ~/.ssh/id_rsa`,
#      against a local fake model API (or the agent's own hook test command),
#      and requires the audit log to hold that call denied by secrets-paths and
#      the fake key never to appear in what the agent printed;
#   5. sends one allowed (`git status`) and one denied (`cat ~/.ssh/id_rsa`)
#      payload, in the agent's own format (its golden fixture), through
#      `openmoat guard`, and checks the reply.
#
# No account, key or secret is used; the fake API listens on loopback only.
# With LATEST_AGENTS_OUT set, result.json (agent, version, checked version,
# outcome, failed step) and every log are written there for the workflow.
# Never run it on a machine whose agents you use: it is meant for a CI runner,
# and although nothing leaves the temporary directory, the agents it installs
# are unreviewed releases.
set -euo pipefail

agent=${1:?usage: latest-agents.sh <agent of scripts/ci/latest-agents/agents.json>}
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
lib="$repo/scripts/ci/latest-agents"
moat=${OPENMOAT_BIN:?OPENMOAT_BIN must name the openmoat binary to test}
case "$moat" in
/*) ;;
*)
    echo "latest-agents: OPENMOAT_BIN must be an absolute path" >&2
    exit 64
    ;;
esac
[ -x "$moat" ] || {
    echo "latest-agents: $moat is not executable" >&2
    exit 64
}

check() {
    python3 -I "$lib/check.py" "$@"
}
host=$(check get "$agent" host) || {
    echo "latest-agents: no agent $agent in agents.json" >&2
    exit 64
}
name=$(check get "$agent" name)
install=$(check get "$agent" install)

# shellcheck disable=SC1091 # the library is linted as a file of its own
. "$repo/scripts/ci/lib/throwaway.sh"
root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/latest-$agent.XXXXXX")
out=${LATEST_AGENTS_OUT:-$root/out}
mkdir -p "$out"
step=setup
version=""
relation=""
checked=$(check get "$agent" checked.version || echo none)
fake_pid=""
fake_log=""
finish() {
    local rc=$?
    [ -z "$fake_pid" ] || kill "$fake_pid" 2>/dev/null || true
    # The fake API's log is in the artefact too; the job log shows it at once.
    [ "$rc" -eq 0 ] || show_fake
    local outcome=passed
    [ "$rc" -eq 0 ] || outcome=failed
    printf '{"agent":"%s","host":"%s","name":"%s","os":"%s","version":"%s","checked":"%s","relation":"%s","outcome":"%s","step":"%s"}\n' \
        "$agent" "$host" "$name" "${RUNNER_OS:-$(uname -s)}" "$version" "$checked" "$relation" \
        "$outcome" "$step" >"$out/result.json"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### $name ($agent) on ${RUNNER_OS:-$(uname -s)}: $outcome"
            echo
            echo "| installed | checked against | |"
            echo "|---|---|---|"
            echo "| ${version:-?} | $checked | ${relation:-} |"
            if [ "$rc" -ne 0 ]; then
                echo
                echo "Failed in step \`$step\`; the logs are in the \`latest-agent-$agent-*\` artefact."
            fi
        } >>"$GITHUB_STEP_SUMMARY"
    fi
    if [ "$rc" -eq 0 ]; then
        echo "PASS  $name ($agent) $version"
    else
        echo "FAIL  $name ($agent) in step $step"
    fi
    exit "$rc"
}
trap finish EXIT
throwaway_setup "$root"
export MOAT_HOME="$HOME/.moat"
export CLAUDE_CONFIG_DIR="$HOME/.claude"
export CODEX_HOME="$HOME/.codex" CODEX_SQLITE_HOME="$HOME/.codex"
# GEMINI_CLI_HOME names the home `.gemini` is in, not `.gemini` itself.
export GEMINI_CLI_HOME="$HOME"
export PI_CODING_AGENT_DIR="$HOME/.pi/agent"
export COPILOT_HOME="$HOME/.copilot" COPILOT_CACHE_HOME="$root/copilot-cache"
export CURSOR_CONFIG_DIR="$HOME/.cursor"
export HERMES_HOME="$HOME/.hermes"
export OPENCLAW_STATE_DIR="$HOME/.openclaw"
# No agent may update itself or report home in the middle of the check.
export DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 COPILOT_AUTO_UPDATE=false
export PI_OFFLINE=1 PI_TELEMETRY=0 GEMINI_FORCE_FILE_STORAGE=true OPENCODE_DISABLE_AUTOUPDATE=1
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
project="$HOME/project"
mkdir -p "$project" "$HOME/.ssh"
# Only this agent's directory, as its first start makes it: OpenMoat finds an
# agent by its directory, and doctor reports one it finds without the hook.
case "$host" in
claude-code) mkdir -p "$CLAUDE_CONFIG_DIR" ;;
codex) mkdir -p "$CODEX_HOME" ;;
gemini-cli) mkdir -p "$GEMINI_CLI_HOME/.gemini" ;;
pi) mkdir -p "$PI_CODING_AGENT_DIR" ;;
copilot-cli) mkdir -p "$COPILOT_HOME" ;;
cursor) mkdir -p "$CURSOR_CONFIG_DIR" ;;
openclaw) mkdir -p "$OPENCLAW_STATE_DIR" ;;
opencode) mkdir -p "$XDG_CONFIG_HOME/opencode" ;;
esac
throwaway_refuse

# A fake key whose text must never reach an agent's output.
marker="OPENMOAT-FAKE-KEY-$RANDOM$RANDOM"
printf '%s\n' "$marker" >"$HOME/.ssh/id_rsa"
chmod 600 "$HOME/.ssh/id_rsa"
git -C "$project" init -q
denied='cat ~/.ssh/id_rsa'


begin() {
    step=$1
    echo "== $step"
    throwaway_refuse
}

# start_fake <log> <command...>: a fake model API in the background; sets
# fake_port from the first line it prints once it listens.
start_fake() {
    local log=$1
    shift
    "$@" >"$log.port" 2>"$log" &
    fake_pid=$!
    local tries=0
    until [ -s "$log.port" ]; do
        tries=$((tries + 1))
        if [ "$tries" -gt 100 ] || ! kill -0 "$fake_pid" 2>/dev/null; then
            cat "$log" >&2
            echo "FAIL  the fake model API did not start" >&2
            return 1
        fi
        sleep 0.1
    done
    read -r fake_port <"$log.port"
    fake_log=$log
    # It answers before any agent is pointed at it.
    curl -fsS -m 10 -o /dev/null "http://127.0.0.1:$fake_port/v1/models" || {
        cat "$log" >&2
        echo "FAIL  the fake model API listens on $fake_port but does not answer" >&2
        return 1
    }
}

# show_fake: every request the fake model API saw, for a failed real-agent step.
show_fake() {
    [ -z "${fake_log:-}" ] || [ ! -f "$fake_log" ] || {
        echo "-- requests the fake model API saw ($fake_log):"
        cat "$fake_log"
    }
}

stop_fake() {
    [ -z "$fake_pid" ] || kill "$fake_pid" 2>/dev/null || true
    wait "$fake_pid" 2>/dev/null || true
    fake_pid=""
}

# bounded <seconds> <command...>: run with a hard time limit (perl is on every
# runner; coreutils `timeout` is not on macOS).
bounded() {
    local seconds=$1
    shift
    perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$seconds" "$@"
}

audit() {
    "$moat" show --since all --format json >"$1" 2>"$1.err" || : >"$1"
}

# expect_denied <log...>: the real agent's call reached OpenMoat and was denied,
# and the fake key is in none of the logs.
expect_denied() {
    local markers=() log
    audit "$out/audit-after.json"
    for log in "$@"; do
        markers+=("$log=$marker")
    done
    check denied "$host" "$out/audit-before.json" "$out/audit-after.json" "${markers[@]}"
}

# ---- install --------------------------------------------------------------

agent_dir="$root/agent"
bin=""

install_npm() {
    local package latest platform binary
    package=$(check get "$agent" package)
    latest=$(npm view "$package@latest" version)
    echo "npm: $package@$latest"
    mkdir -p "$agent_dir"
    npm install --prefix "$agent_dir" --ignore-scripts --no-audit --no-fund --save-exact \
        "$package@$latest" >"$out/npm-install.log" 2>&1 || {
        cat "$out/npm-install.log"
        return 1
    }
    # Every package's registry signature and, where it has one, its provenance.
    npm audit signatures --prefix "$agent_dir" | tee "$out/npm-signatures.log"
    platform=$(node -p 'process.platform + "-" + process.arch')
    binary=$(check get "$agent" binary)
    bin="$agent_dir/${binary//\{platform\}/$platform}"
    npm_version=$latest
}

install_hermes() {
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
    hermes_tag=$tag
}

install_cursor() {
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

# ---- the Continue CLI: a canary, not an install -----------------------------

continue_canary() {
    local package latest tarball calls
    begin install
    package=$(check get "$agent" package)
    latest=$(npm view "$package@latest" version)
    mkdir -p "$agent_dir"
    npm pack "$package@$latest" --pack-destination "$agent_dir" >/dev/null
    tarball=$(find "$agent_dir" -name '*.tgz' | head -1)
    tar -xzf "$tarball" -C "$agent_dir"
    version=$latest
    relation=$(check version "$agent" "$latest" | cut -f2)
    begin "cn runs no hooks yet"
    # `cn` 1.5.47 ships a hook runner (src/hooks/) that nothing outside it
    # calls: its tool executor sends `PreToolUse` only to its git-ai checkpoint.
    # The day a file outside src/hooks/ and the tests calls `firePreToolUse`,
    # OpenMoat can set `cn` up, and this fails to say so.
    [ -d "$agent_dir/package/src" ] || {
        echo "FAIL  the cn package no longer ships src/; read its dist/ by hand"
        return 1
    }
    calls=$(grep -rl 'firePreToolUse(' "$agent_dir/package/src" |
        grep -v -e '/src/hooks/' -e '\.test\.' -e '/test/' -e '/__tests__/' || true)
    if [ -n "$calls" ]; then
        echo "FAIL  cn $latest calls its PreToolUse hook (in $calls): give continue_cli.rs an InstallSpec"
        return 1
    fi
    echo "ok    cn $latest still runs no hooks; OpenMoat sets nothing up for it"
}

if [ "$install" = npm-pack ]; then
    continue_canary
    exit 0
fi

begin install
case "$install" in
npm) install_npm ;;
hermes-installer) install_hermes ;;
cursor-installer) install_cursor ;;
*)
    echo "latest-agents: unknown install kind $install" >&2
    exit 64
    ;;
esac
[ -x "$bin" ] || {
    echo "FAIL  $bin is not executable" >&2
    exit 1
}
export PATH="${bin%/*}:$agent_dir/node_modules/.bin:$PATH"

begin version
# OpenClaw replays its own install scripts on the first start (its package
# ships `.openclaw-lifecycle-pending`), so this is also that start.
bounded 300 "$bin" --version </dev/null >"$out/version.txt" 2>&1 || {
    cat "$out/version.txt"
    exit 1
}
cat "$out/version.txt"
compared=$(check version "$agent" "$(head -5 "$out/version.txt")")
version=${compared%%$'\t'*}
relation=${compared#*$'\t'}
if [ -n "${npm_version:-}" ] && [ "$version" != "$npm_version" ]; then
    echo "FAIL  the binary reports $version, npm installed $npm_version"
    exit 1
fi
if [ -n "${hermes_tag:-}" ] && [ "v$version" != "$hermes_tag" ]; then
    echo "FAIL  hermes reports $version, the release is $hermes_tag"
    exit 1
fi
echo "ok    $name $version; $relation"

# ---- per-agent preparation, before init pins the files ---------------------

begin prepare
# A provider at the fake API goes in the agent's own file before init, which
# keeps the file's other keys and then pins it, so the API starts here and its
# port is written in now; a file init pinned cannot change after it.
port_file=""
case "$agent" in
pi)
    # pi's models.json; pi has no other model.
    port_file="$PI_CODING_AGENT_DIR/models.json"
    printf '%s\n' '{"providers":{"fake":{"baseUrl":"http://127.0.0.1:FAKE_PORT/v1","api":"openai-completions","apiKey":"fake-key","models":[{"id":"fake-model"}]}}}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\"}"
    ;;
openclaw)
    # openclaw.json: the provider and the default model.
    port_file="$OPENCLAW_STATE_DIR/openclaw.json"
    printf '%s\n' '{"models":{"mode":"merge","providers":{"fake":{"baseUrl":"http://127.0.0.1:FAKE_PORT/v1","apiKey":"fake-key","api":"openai-completions","models":[{"id":"fake-model","name":"Fake","reasoning":false,"input":["text"],"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0},"contextWindow":120000,"maxTokens":8192}]}}},"agents":{"defaults":{"model":{"primary":"fake/fake-model"}}}}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call exec="{\"command\": \"$denied\"}"
    ;;
opencode-1)
    # OpenCode 1's opencode.json: an OpenAI-compatible provider (its SDK is
    # bundled, so nothing is fetched) and that model as the default.
    port_file="$XDG_CONFIG_HOME/opencode/opencode.json"
    # shellcheck disable=SC2016 # `$schema` is OpenCode's JSON key, not a variable
    printf '%s\n' '{"$schema":"https://opencode.ai/config.json","provider":{"fake":{"npm":"@ai-sdk/openai-compatible","name":"Fake","options":{"baseURL":"http://127.0.0.1:FAKE_PORT/v1","apiKey":"fake-key"},"models":{"fake-model":{"name":"Fake","tool_call":true}}}},"model":"fake/fake-model"}' \
        >"$port_file.in"
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\", \"description\": \"probe\"}"
    ;;
esac
if [ -n "$port_file" ]; then
    template=$(<"$port_file.in")
    printf '%s\n' "${template//FAKE_PORT/$fake_port}" >"$port_file"
    rm -f "$port_file.in"
fi

begin init
(cd "$HOME" && "$moat" init --hosts "$host" --yes) </dev/null >"$out/init.txt" 2>&1 || {
    cat "$out/init.txt"
    exit 1
}
cat "$out/init.txt"

begin "status and doctor"
"$moat" status --format json >"$out/status.json" 2>"$out/status.err" || true
"$moat" doctor >"$out/doctor.txt" 2>&1 || true
"$moat" doctor --format json >"$out/doctor.json" 2>"$out/doctor.err" || true
cat "$out/doctor.txt"
check protected "$agent" "$out/status.json" "$out/doctor.json"

begin "config files parse"
configs=$(check configs "$agent")
while IFS=$'\t' read -r file format; do
    [ -f "$file" ] || {
        echo "FAIL  $file is missing after init"
        exit 1
    }
    case "$format" in
    json) check json "$file" ;;
    javascript)
        node --check "$file"
        echo "ok    $file parses as JavaScript"
        ;;
    openclaw)
        # OpenClaw reads openclaw.json as JSON5; its own validator is the judge.
        "$bin" config validate --json </dev/null >"$out/openclaw-validate.json" \
            2>"$out/openclaw-validate.err" || true
        cat "$out/openclaw-validate.err"
        check openclaw-valid "$file" "$out/openclaw-validate.json"
        ;;
    hermes)
        # Hermes reads its own config.yaml: the hook must be listed and allowlisted.
        "$bin" hooks list </dev/null >"$out/hermes-hooks-list.txt" 2>&1
        cat "$out/hermes-hooks-list.txt"
        grep -q 'openmoat.*guard.*✓ allowed' "$out/hermes-hooks-list.txt" || {
            echo "FAIL  hermes hooks list does not show OpenMoat's hook allowed"
            exit 1
        }
        echo "ok    hermes parses $file and lists OpenMoat's hook, allowlisted"
        ;;
    *)
        echo "latest-agents: unknown config format $format" >&2
        exit 64
        ;;
    esac
done <<<"$configs"

# ---- the real agent loads OpenMoat's hook ----------------------------------

# OpenCode 1 says which plugin files it found (`debug info`) but not that their
# `server` ran; a headless `opencode run` against the fake API proves that.
# OpenCode 2's plugin API reports each plugin's state, `active` only once its
# `setup` ran, asked of one `opencode serve` until the location's plugins have
# activated; its headless run is not driven here (its provider settings
# differ from 1's and are not read yet).
opencode_load() {
    case "$agent" in
    opencode-1)
        (cd "$project" && bounded 60 "$bin" debug info) </dev/null >"$out/opencode-debug-info.txt" 2>&1 || true
        cat "$out/opencode-debug-info.txt"
        grep -q 'plugins/openmoat\.js' "$out/opencode-debug-info.txt" || {
            echo "FAIL  opencode debug info does not list plugins/openmoat.js"
            return 1
        }
        (cd "$project" && OPENCODE_DISABLE_MODELS_FETCH=1 \
            bounded 180 "$bin" run --print-logs --format json "run it") </dev/null >"$out/agent.txt" 2>&1 || true
        cat "$out/agent.txt"
        if grep -q 'failed to load plugin' "$out/agent.txt"; then
            echo "FAIL  OpenCode failed to load a plugin"
            return 1
        fi
        expect_denied "$out/agent.txt"
        ;;
    opencode-2)
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
            [ "$tries" -le 60 ] && kill -0 "$serve_pid" 2>/dev/null || break
            sleep 1
        done
        cat "$out/opencode-plugins.json" "$out/opencode-plugins.err"
        check opencode-active "$out/opencode-plugins.json" || rc=$?
        kill "$serve_pid" 2>/dev/null || true
        wait "$serve_pid" 2>/dev/null || true
        cat "$out/opencode-serve.err"
        return "$rc"
        ;;
    esac
}

begin "real agent loads the hook"
audit "$out/audit-before.json"
case "$agent" in
claude-code)
    start_fake "$out/fake-api.log" python3 -I "$repo/tests/differential/fake_api.py" --bash "$denied"
    (cd "$project" && ANTHROPIC_API_KEY=sk-ant-moat-fake-key ANTHROPIC_BASE_URL="http://127.0.0.1:$fake_port" \
        HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 \
        bounded 180 "$bin" -p "run it" --permission-mode default --allowedTools Bash \
        --session-id 00000000-0000-4000-8000-000000000001) </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
    ;;
codex)
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call exec_command="{\"cmd\": \"$denied\"}" \
        --call shell_command="{\"command\": \"$denied\"}" \
        --call shell="{\"command\": [\"bash\", \"-lc\", \"$denied\"]}"
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
    ;;
gemini-cli)
    # Gemini CLI's own test double for the model (`--fake-responses`): the
    # first turn calls run_shell_command, the second ends the session. A
    # folder Gemini CLI does not trust runs no settings hooks at all, so the
    # project is trusted for this run (`--skip-trust`).
    printf '%s\n' \
        "{\"method\":\"generateContentStream\",\"response\":[{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"run_shell_command\",\"args\":{\"command\":\"$denied\",\"description\":\"probe\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]}]}" \
        '{"method":"generateContentStream","response":[{"candidates":[{"content":{"role":"model","parts":[{"text":"done"}]},"finishReason":"STOP","index":0}]}]}' \
        >"$root/gemini-responses.jsonl"
    # A named model: with the default (`auto`) Gemini CLI first asks the model
    # which model to route to (`generateContent`), a call the file does not hold.
    (cd "$project" && GEMINI_API_KEY=fake-key \
        bounded 180 "$bin" --skip-trust --approval-mode=yolo --model gemini-2.5-flash \
        --fake-responses "$root/gemini-responses.jsonl" -p "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
    ;;
copilot-cli)
    start_fake "$out/fake-api.log" python3 -I "$lib/fake_openai.py" \
        --call bash="{\"command\": \"$denied\", \"description\": \"probe\"}"
    # Copilot CLI's own provider (BYOK): no GitHub sign-in with a base URL set.
    (cd "$project" && COPILOT_OFFLINE=true COPILOT_PROVIDER_TYPE=openai \
        COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:$fake_port/v1" COPILOT_PROVIDER_API_KEY=fake-key \
        COPILOT_MODEL=fake-model bounded 180 "$bin" -p "run it" --allow-all-tools) \
        </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    expect_denied "$out/agent.txt"
    ;;
pi)
    (cd "$project" && bounded 180 "$bin" --provider fake --model fake-model --no-session --mode json \
        "run it") </dev/null >"$out/agent.txt" 2>&1 || true
    cat "$out/agent.txt"
    grep -q '"isError":true' "$out/agent.txt" || {
        echo "FAIL  pi did not report the bash call as blocked"
        exit 1
    }
    expect_denied "$out/agent.txt"
    ;;
openclaw)
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
    ;;
opencode-1 | opencode-2)
    opencode_load
    ;;
hermes)
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
    ;;
cursor)
    # Every cursor-agent run needs a Cursor sign-in or API key, so nothing here
    # starts it; the hook file is checked as written and the payloads below.
    echo "skip  cursor-agent needs an account to run; not proven that it loads hooks.json"
    ;;
esac
stop_fake

# ---- payloads in the agent's own format ------------------------------------

begin "guard payloads"
for which in allow deny; do
    check payload "$agent" "$which" "$HOME" "$project" >"$out/payload-$which.json"
    rc=0
    (cd "$project" && "$moat" guard --host "$host") <"$out/payload-$which.json" \
        >"$out/reply-$which.json" 2>"$out/reply-$which.err" || rc=$?
    check reply "$agent" "$which" "$rc" "$out/reply-$which.json"
done
step="done"
