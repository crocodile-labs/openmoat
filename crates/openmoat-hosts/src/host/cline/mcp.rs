//! How Cline names an MCP server's tools.

use crate::contract::McpNames;

/// `<server>__<tool>` with every run of characters but letters, digits, `_`
/// and `-` as one `_`, cut and hashed when longer than 64 characters
/// (`defaultMcpToolNameTransform` in `extensions/mcp/name-transform.ts`),
/// recorded as `mcp__<server>__<tool>`.
#[derive(Debug)]
pub(crate) struct Spelled;

impl McpNames for Spelled {
    fn tool_of(&self, tool: &str, name: &str) -> bool {
        tool.starts_with(&format!("mcp__{}__", spell(name)))
    }
}

/// `name` with each run of characters outside `[A-Za-z0-9_-]` as one `_`.
fn spell(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_is_traced_to_its_server_as_cline_spells_it() {
        assert!(Spelled.tool_of("mcp__my_files__read", "my files"));
        assert!(Spelled.tool_of("mcp__a_b__x", "a.:b"));
        assert!(Spelled.tool_of("mcp__internal-tools__run", "internal-tools"));
        assert!(!Spelled.tool_of("mcp__other__run", "internal-tools"));
    }
}
