//! Codex `config.toml`: `[mcp_servers.<name>]`.

use serde_json::Value;

use crate::contract::{McpReader, McpServer, McpSyntax, servers_at};

#[derive(Debug)]
pub(crate) struct ConfigToml;

impl McpReader for ConfigToml {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Toml
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        Ok(servers_at(doc, "mcp_servers", "/mcp_servers"))
    }
}
