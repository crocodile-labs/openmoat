//! The row for `claude-code`.
//!
//! Uninstall: `uninstall.rs`; an edited hook file: `lock.rs`; a secret
//! read and a review: `guard.rs`; another agent's payload: `guard.rs`.

use super::{PRE_TOOL_USE, Row, notification, pre_tool_use};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "claude-code",
        hook: "claude-code",
        governed: "claude-code/bash.json",
        // A tool OpenMoat's matcher does not name is another agent's
        // (ADR-097), checked for what its arguments name.
        unknown_tool: || pre_tool_use("FutureTool"),
        checks_unknown_tools: true,
        unknown_event: notification,
        ungoverned: &[|_| fixture("claude-code/skill.json")],
        // MCP servers: `mcp.rs`.
        ..PRE_TOOL_USE
    }
}
