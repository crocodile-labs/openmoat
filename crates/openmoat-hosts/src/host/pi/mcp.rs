//! How pi names an MCP server's tools.

use crate::contract::{McpNames, spelled};

/// `mcp__<server>__<tool>` with every character but letters, digits and `_`
/// as `_`, `-` included (pi 1.3.0 `docs/mcp.md`, "Configuration rules").
#[derive(Debug)]
pub(crate) struct Underscored;

impl McpNames for Underscored {
    fn tool_of(&self, tool: &str, name: &str) -> bool {
        tool.starts_with(&format!("mcp__{}__", spelled(name, |c| c == '_', '_')))
    }
}
