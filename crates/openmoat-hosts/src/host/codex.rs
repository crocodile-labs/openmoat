//! The Codex CLI: `PreToolUse` in Claude Code's format
//! ([`crate::wire::pre_tool_use`]).

use crate::contract::{Asks, HostSpec};

/// Codex's `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and
/// then runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: Some("Codex hooks cannot ask"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};
