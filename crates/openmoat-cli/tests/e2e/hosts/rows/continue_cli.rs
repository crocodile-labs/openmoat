//! The row for `continue`.
//!
//! An ask: `continue_cli.rs`.

use super::{PRE_TOOL_USE, Row, post_tool_use, pre_tool_use};

pub fn row() -> Row {
    Row {
        id: "continue",
        hook: "claude-code",
        env: Some("CONTINUE_PROJECT_DIR"),
        governed: "continue/pretooluse-bash.json",
        unknown_tool: || pre_tool_use("FutureTool"),
        unknown_event: post_tool_use,
        ..PRE_TOOL_USE
    }
}
