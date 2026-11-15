//! Crush's MCP servers: the `mcp` object of each `crush.json`, a server per
//! key with `type` (`stdio`, `sse` or `http`), `command`, `args`, `env`,
//! `url`, `headers` and `disabled` (`MCPConfig` in
//! `internal/config/config.go`).

use serde_json::Value;

use crate::contract::{McpReader, McpServer, McpSyntax, servers_at};

#[derive(Debug)]
pub(super) struct CrushJson;

impl McpReader for CrushJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        match doc.get("mcp") {
            None | Some(Value::Null | Value::Object(_)) => Ok(servers_at(doc, "mcp", "/mcp")),
            Some(_) => Err("`mcp` is not an object of servers".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn each_key_of_mcp_is_a_server() {
        let doc = json!({"mcp": {
            "files": {"type": "stdio", "command": "npx", "args": ["files"]},
            "docs": {"type": "http", "url": "https://example.com/mcp"},
        }});
        let servers = CrushJson.servers(&doc).unwrap();
        let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"files") && names.contains(&"docs"));
        assert!(servers.iter().any(|s| s.pointer == "/mcp/files"));
        assert_eq!(CrushJson.servers(&json!({})).unwrap().len(), 0);
        assert!(CrushJson.servers(&json!({"mcp": []})).is_err());
    }
}
