//! Hermes Agent's MCP servers (`mcp_servers` in `config.yaml`) and how it
//! names their tools.

use serde_json::Value;

use crate::contract::{McpNames, McpReader, McpServer, McpSyntax, servers_at};

/// `mcp_servers: {<name>: {command, args, env, url, headers, …}}` in YAML.
#[derive(Debug)]
pub(crate) struct McpServersYaml;

impl McpReader for McpServersYaml {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Yaml
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        match doc.get("mcp_servers") {
            None | Some(Value::Null | Value::Object(_)) => {
                Ok(servers_at(doc, "mcp_servers", "/mcp_servers"))
            }
            Some(_) => Err("`mcp_servers` is not a mapping of servers".to_owned()),
        }
    }
}

/// Longest tool name Hermes registers (`_MCP_TOOL_NAME_MAX_LENGTH`).
const MAX_NAME: usize = 64;
/// The `_` and hex digits Hermes ends a shortened name with.
const HASH_SUFFIX: usize = 9;

/// `mcp__<server>__<tool>`, each part with every character but ASCII letters,
/// digits and `_` as `_`; a name longer than 64 characters is cut to 55 and
/// ends in `_` and 8 hex digits of its hash (`mcp_prefixed_tool_name` in
/// `tools/mcp_tool_schema.py`, v0.22.5). The CLI's own check covers the full
/// form; this one covers a cut name whose kept part starts with the server's
/// prefix, or is all of it that fits.
#[derive(Debug)]
pub(crate) struct HermesNames;

impl McpNames for HermesNames {
    fn tool_of(&self, tool: &str, server: &str) -> bool {
        let prefix = format!("mcp__{}__", crate::contract::spelled(server, |c| c == '_', '_'));
        if tool.starts_with(&prefix) {
            return true;
        }
        let kept = MAX_NAME - HASH_SUFFIX;
        tool.len() == MAX_NAME
            && tool.is_char_boundary(kept)
            && tool[kept..].starts_with('_')
            && tool[kept + 1..].chars().all(|c| c.is_ascii_hexdigit())
            && prefix.starts_with(&tool[..kept])
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn servers_are_read_from_mcp_servers() {
        let doc = json!({ "mcp_servers": { "files": { "command": "npx" } } });
        let servers = McpServersYaml.servers(&doc).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].pointer, "/mcp_servers/files");
        assert!(McpServersYaml.servers(&json!({})).unwrap().is_empty());
        assert!(McpServersYaml.servers(&json!({ "mcp_servers": [1] })).is_err());
    }

    #[test]
    fn tool_names_follow_hermes_spelling_and_shortening() {
        assert!(HermesNames.tool_of("mcp__my_server__read", "my-server"));
        assert!(HermesNames.tool_of("mcp__a_b__x", "a.b"));
        assert!(!HermesNames.tool_of("mcp__other__read", "my-server"));
        let long_server = "s".repeat(60);
        let full = format!("mcp__{long_server}__tool");
        let cut = format!("{}_0123abcd", &full[..55]);
        assert_eq!(cut.len(), 64);
        assert!(HermesNames.tool_of(&cut, &long_server));
        assert!(!HermesNames.tool_of(&cut, "s"));
    }
}
