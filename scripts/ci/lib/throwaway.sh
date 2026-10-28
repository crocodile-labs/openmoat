# shellcheck shell=bash
# A throwaway home for scripts that install agents and run `openmoat init` in
# CI (scripts/ci/latest-agents.sh, scripts/ci/clean-install.sh). Sourced, not
# run. Nothing these scripts do may reach the runner's own home or any agent
# configuration outside the temporary directory:
#
#   throwaway_setup <dir>   make <dir> the root; HOME, the XDG directories,
#                           npm's cache and config and TMPDIR move under it
#   throwaway_refuse        exit 64 unless every variable an agent or OpenMoat
#                           reads its state from, that is set, resolves inside
#                           the root; run it before every command that writes
#
# The variables are those OpenMoat's host specs name and those the agents
# document for their own state (scripts/ci/latest-agents/README.md).

# Every variable that moves a place an agent or OpenMoat keeps state in.
THROWAWAY_VARIABLES=(HOME TMPDIR MOAT_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME
    XDG_CACHE_HOME CLAUDE_CONFIG_DIR CODEX_HOME CODEX_SQLITE_HOME GEMINI_CLI_HOME
    PI_CODING_AGENT_DIR PI_CODING_AGENT_SESSION_DIR COPILOT_HOME COPILOT_CACHE_HOME
    CURSOR_CONFIG_DIR OPENCODE_CONFIG_DIR HERMES_HOME OPENCLAW_HOME OPENCLAW_STATE_DIR
    OPENCLAW_CONFIG_PATH CONTINUE_GLOBAL_DIR CARGO_HOME npm_config_cache npm_config_prefix
    npm_config_userconfig HOMEBREW_CACHE)

# The physical path of $1: its deepest existing ancestor resolved, the rest
# appended. A `..` component is refused rather than reasoned about.
throwaway_resolve() {
    local path=$1 rest=""
    case "/$path/" in
    */../*)
        echo "throwaway: $path has a .. component" >&2
        return 1
        ;;
    esac
    while [ ! -e "$path" ] && [ ! -L "$path" ] && [ "$path" != "/" ]; do
        rest="/${path##*/}$rest"
        path=${path%/*}
        [ -n "$path" ] || path=/
    done
    # A file (npm's config file, OpenClaw's config path) resolves through its
    # directory; a link, file or directory, through its target.
    if [ -L "$path" ]; then
        path=$(readlink -f "$path") || return 1
    fi
    if [ -d "$path" ]; then
        printf '%s%s\n' "$(cd "$path" && pwd -P)" "$rest"
    else
        printf '%s/%s%s\n' "$(cd "${path%/*}" && pwd -P)" "${path##*/}" "$rest"
    fi
}

throwaway_setup() {
    THROWAWAY_ROOT=$(throwaway_resolve "$1")
    THROWAWAY_REAL_HOME=$(throwaway_resolve "${HOME:?HOME is not set}")
    case "$THROWAWAY_ROOT/" in
    "$THROWAWAY_REAL_HOME"/.*)
        echo "throwaway: $THROWAWAY_ROOT is inside a dot directory of the real home" >&2
        exit 64
        ;;
    esac
    export HOME="$THROWAWAY_ROOT/home"
    export TMPDIR="$THROWAWAY_ROOT/tmp"
    export XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
    export XDG_STATE_HOME="$HOME/.local/state" XDG_CACHE_HOME="$HOME/.cache"
    export npm_config_cache="$THROWAWAY_ROOT/npm-cache"
    export npm_config_userconfig="$THROWAWAY_ROOT/npmrc"
    export npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
    export GIT_CONFIG_NOSYSTEM=1
    # Variables a person or the runner may have set that would point an agent,
    # OpenMoat or a build elsewhere; a script that needs one sets it again
    # inside the root (GitHub's Ubuntu image sets CARGO_HOME).
    unset GEMINI_CLI_TRUSTED_FOLDERS_PATH OPENCODE_CONFIG OPENCODE_CONFIG_CONTENT CARGO_HOME \
        MOAT_HOME CLAUDE_CONFIG_DIR CODEX_HOME GEMINI_CLI_HOME PI_CODING_AGENT_DIR COPILOT_HOME \
        CURSOR_CONFIG_DIR OPENCODE_CONFIG_DIR HERMES_HOME OPENCLAW_HOME OPENCLAW_STATE_DIR \
        OPENCLAW_CONFIG_PATH CONTINUE_GLOBAL_DIR npm_config_prefix HOMEBREW_CACHE
    mkdir -p "$HOME" "$TMPDIR" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" \
        "$XDG_CACHE_HOME" "$npm_config_cache"
    : >"$npm_config_userconfig"
    chmod 700 "$THROWAWAY_ROOT" "$HOME"
}

throwaway_refuse() {
    local var here
    for var in "${THROWAWAY_VARIABLES[@]}"; do
        [ -n "${!var:-}" ] || continue
        here=$(throwaway_resolve "${!var}") || exit 64
        case "$here/" in
        "$THROWAWAY_ROOT"/?*) ;;
        *)
            echo "throwaway: $var=$here is outside $THROWAWAY_ROOT; refusing to run" >&2
            exit 64
            ;;
        esac
        if [ "$here" = "$THROWAWAY_REAL_HOME" ]; then
            echo "throwaway: $var is the real home; refusing to run" >&2
            exit 64
        fi
    done
}
