//! GitHub Copilot CLI's MCP files and tool names.

use serde_json::Value;

use crate::contract::{
    McpNames, McpReader, McpServer, McpServersJson, McpSyntax, escape, server, spelled,
};

/// The project files, which may hold the servers under `mcpServers` or bare,
/// each top-level key a server
/// (<https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers>).
#[derive(Debug)]
pub(crate) struct JsonOrBare;

impl McpReader for JsonOrBare {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        let mut out = McpServersJson.servers(doc)?;
        // Read whichever way the file is laid out: a top-level entry that
        // looks like a server is pinned too, so a bare file cannot start a
        // server OpenMoat did not see.
        for (name, entry) in doc.as_object().into_iter().flatten() {
            if name != "mcpServers" && looks_like_server(entry) {
                out.push(server(format!("/{}", escape(name)), name, entry));
            }
        }
        Ok(out)
    }
}

/// An object naming how a server starts or is reached.
fn looks_like_server(entry: &Value) -> bool {
    ["command", "url", "type"]
        .iter()
        .any(|key| entry.get(key).is_some())
}

/// `<server>-<tool>`: the hook sees only the name the model calls; the
/// built-in GitHub server's tools are `github-mcp-server-…`.
#[derive(Debug)]
pub(crate) struct Dashed;

impl McpNames for Dashed {
    fn tool_of(&self, tool: &str, name: &str) -> bool {
        [
            name.to_owned(),
            spelled(name, |c| c == '_' || c == '-', '-'),
            spelled(name, |c| c == '_' || c == '-', '_'),
        ]
        .iter()
        .any(|n| tool.starts_with(&format!("{n}-")))
    }
}
