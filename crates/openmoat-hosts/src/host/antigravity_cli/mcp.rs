//! How Antigravity CLI names an MCP server's tools to its hooks.

use crate::contract::McpNames;

/// `mcp_<server>_<tool>` is the eager tool's name to the model (`/docs/mcp`);
/// the documentation does not say what name hooks receive. Lazy tools go
/// through `call_mcp_tool`, which names the server and is recorded as
/// `mcp__<server>__<tool>`. The name can match too much only by holding back
/// another server's tools while one is unaccepted.
#[derive(Debug)]
pub(super) struct Names;

impl McpNames for Names {
    fn tool_of(&self, tool: &str, server: &str) -> bool {
        tool.starts_with(&format!("mcp_{server}_"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eager_names_are_told_by_the_server_prefix() {
        assert!(Names.tool_of("mcp_github_issues", "github"));
        assert!(!Names.tool_of("mcp_github_issues", "git"));
        assert!(!Names.tool_of("view_file", "github"));
    }
}
