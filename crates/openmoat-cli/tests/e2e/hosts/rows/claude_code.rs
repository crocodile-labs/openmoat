//! The row for `claude-code`.
//!
//! Uninstall: `uninstall.rs`; an edited hook file: `lock.rs`; a secret
//! read and an ask: `guard.rs`.

use super::{PRE_TOOL_USE, Row, post_tool_use, pre_tool_use};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "claude-code",
        hook: "claude-code",
        governed: "claude-code/bash.json",
        unknown_tool: || pre_tool_use("FutureTool"),
        unknown_event: post_tool_use,
        ungoverned: &[|_| fixture("claude-code/ungoverned.json")],
        // MCP servers: `mcp.rs`.
        ..PRE_TOOL_USE
    }
}
