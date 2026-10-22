//! Claude Code's `~/.claude.json`: `mcpServers` for the user and
//! `projects.<path>.mcpServers` for each project's local servers.

use serde_json::Value;

use crate::contract::{McpReader, McpServer, McpServersJson, McpSyntax, escape, servers_at};

#[derive(Debug)]
pub(crate) struct ClaudeJson;

impl McpReader for ClaudeJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        let mut out = McpServersJson.servers(doc)?;
        if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
            for (project, settings) in projects {
                let at = format!("/projects/{}/mcpServers", escape(project));
                out.extend(servers_at(settings, "mcpServers", &at));
            }
        }
        Ok(out)
    }
}
