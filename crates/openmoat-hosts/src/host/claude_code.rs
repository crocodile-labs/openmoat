//! Anthropic's Claude Code: `PreToolUse` ([`crate::wire::pre_tool_use`]) and
//! `ConfigChange` ([`config_change`]).

use crate::contract::{Asks, HostSpec};

pub(crate) mod config_change;

/// Claude Code asks on `PreToolUse`, except in a permission mode that puts no
/// question to a person (`bypassPermissions`, `dontAsk`).
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "claude-code",
    display_name: "Claude Code",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Claude Code's permission mode does not ask"),
        defer_is_ask_on_no_ask: false,
    },
};
