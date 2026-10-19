//! The facts about every supported host, one [`HostSpec`] each.

use crate::Host;
use crate::contract::{Asks, HostSpec};

/// Anthropic's Claude Code. It asks on `PreToolUse`, except in a permission
/// mode that puts no question to a person (`bypassPermissions`, `dontAsk`).
pub(crate) static CLAUDE_CODE: HostSpec = HostSpec {
    id: "claude-code",
    display_name: "Claude Code",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Claude Code's permission mode does not ask"),
        defer_is_ask_on_no_ask: false,
    },
};

/// The Codex CLI. Its `PreToolUse` rejects `permissionDecision: "ask"` as
/// unsupported and then runs the call.
pub(crate) static CODEX: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: Some("Codex hooks cannot ask"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};

/// Cursor. `preToolUse` accepts `ask` but runs the call, and `beforeReadFile`
/// takes only allow or deny; both run file tools outside Cursor's sandbox, so a
/// `defer` there is an `ask`. Only file tools reach these hooks, and
/// `moat allow --last` approves the exact file.
pub(crate) static CURSOR: HostSpec = HostSpec {
    id: "cursor",
    display_name: "Cursor",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Cursor does not prompt for this hook"),
        defer_is_ask_on_no_ask: true,
    },
};

/// The Continue CLI (`cn`). It sends Claude Code's hooks, ignores `ask` and
/// runs the call.
pub(crate) static CONTINUE: HostSpec = HostSpec {
    id: "continue",
    display_name: "Continue CLI",
    speaks: Some(Host::ClaudeCode),
    asks: Asks {
        on_pre_tool_use: Some("the Continue CLI runs a call its hook asks about"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};

/// OpenClaw, through OpenMoat's plugin and its `before_tool_call` hook.
pub(crate) static OPENCLAW: HostSpec = HostSpec {
    id: "openclaw",
    display_name: "OpenClaw",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};
