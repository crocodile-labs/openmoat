//! OpenClaw's MCP servers (`mcp.servers` in `openclaw.json`, JSON5) and how it
//! names their tools.

use serde_json::Value;

use crate::contract::{McpNames, McpReader, McpServer, McpSyntax, servers_at};

/// `{mcp: {servers: {"<name>": {...}}}}`.
#[derive(Debug)]
pub(crate) struct OpenClawJson;

impl McpReader for OpenClawJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json5
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        refuse_include(doc)?;
        Ok(doc
            .get("mcp")
            .map(|mcp| servers_at(mcp, "servers", "/mcp/servers"))
            .unwrap_or_default())
    }
}

/// OpenClaw merges in the files an `$include` key names; one where MCP
/// servers may come from hides which servers OpenClaw starts.
fn refuse_include(root: &Value) -> Result<(), String> {
    for at in ["", "/mcp", "/mcp/servers"] {
        if root
            .pointer(at)
            .and_then(Value::as_object)
            .is_some_and(|o| o.contains_key("$include"))
        {
            let place = if at.is_empty() { "the top level" } else { at };
            return Err(format!(
                "`$include` at {place} may bring MCP servers from another file, which OpenMoat \
                 does not read; move `mcp.servers` into this file"
            ));
        }
    }
    Ok(())
}

/// OpenClaw names a server's tools `<prefix>__<tool>`
/// (<https://docs.openclaw.ai/plugins/bundles>, "Tool naming"; its
/// `agent-bundle-mcp-names` module): the prefix is the server's name with
/// every character but letters, digits, `_` and `-` as `-`, `mcp` in front of
/// one that does not start with a letter, at most 30 characters, and `-2`,
/// `-3`, … on a shortened base when another server's prefix is the same
/// without regard to case.
#[derive(Debug)]
pub(crate) struct OpenClawNames;

impl McpNames for OpenClawNames {
    fn tool_of(&self, tool: &str, name: &str) -> bool {
        openclaw_tool_of(tool, name)
    }
}

fn openclaw_tool_of(tool: &str, name: &str) -> bool {
    const MAX_PREFIX: usize = 30;
    let Some(rest) = tool.strip_prefix("mcp__") else {
        return false;
    };
    let spelled: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let mut bases = vec![spelled.clone()];
    if !spelled.starts_with(|c: char| c.is_ascii_alphabetic()) {
        bases.extend(["mcp", "mcp-", "mcp_"].map(|fallback| format!("{fallback}{spelled}")));
    }
    let bases: Vec<String> = bases
        .into_iter()
        .map(|b| b.chars().take(MAX_PREFIX).collect())
        .collect();
    // Every `__` in the tool may end the prefix: a prefix may hold `__` too.
    let lower = rest.to_ascii_lowercase();
    lower.match_indices("__").any(|(end, _)| {
        let prefix = &lower[..end];
        bases.iter().any(|base| {
            prefix == base
                || prefix.rsplit_once('-').is_some_and(|(stem, n)| {
                    !stem.is_empty()
                        && prefix.len() <= MAX_PREFIX
                        && n.parse::<u32>().is_ok_and(|n| n >= 2)
                        && base.starts_with(stem)
                })
        })
    })
}
