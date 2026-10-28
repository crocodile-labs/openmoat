//! OpenCode's MCP servers (`mcp.<name>` in its JSONC configuration files) and
//! how it names their tools.

use serde_json::Value;

use crate::contract::{McpNames, McpReader, McpServer, McpSyntax, servers_at};

/// `{"mcp": {"<name>": {"type": "local" | "remote", …}}}` (OpenCode 1
/// `docs/mcp-servers.mdx`, `config/config.ts`), and OpenCode 2's
/// `{"mcp": {"servers": {"<name>": …}, "timeout": …}}`, which OpenCode 2 reads
/// beside the old shape: a `servers` or `timeout` key is a server of the old
/// shape only when it has a `type` of `local` or `remote` (2.2.0
/// `core/src/config/normalize.ts:266-305,859-861`). JSON with comments and
/// trailing commas, read as JSON5.
#[derive(Debug)]
pub(crate) struct OpenCodeJson;

impl McpReader for OpenCodeJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json5
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        let legacy_shape =
            |entry: &Value| matches!(entry.get("type").and_then(Value::as_str), Some("local" | "remote"));
        let mut servers: Vec<McpServer> = servers_at(doc, "mcp", "/mcp")
            .into_iter()
            .filter(|s| !matches!(s.name.as_str(), "servers" | "timeout") || legacy_shape(&s.entry))
            .collect();
        if let Some(native) = doc.get("mcp").and_then(|m| m.get("servers"))
            && !legacy_shape(native)
        {
            servers.extend(servers_at(&serde_json::json!({ "s": native }), "s", "/mcp/servers"));
        }
        Ok(servers)
    }
}

/// `<server>_<tool>`, each with every character but letters, digits, `_` and
/// `-` as `_` (`mcp/catalog.ts`, `toolName`). A `_` in a server's name makes
/// the split ambiguous, so every server whose spelling begins the tool's name
/// counts, in the name OpenCode sends and in the `mcp__<server>__<tool>` the
/// adapter decides it as: matching too much only holds back another server's
/// tools while one is unaccepted.
#[derive(Debug)]
pub(crate) struct Joined;

impl McpNames for Joined {
    fn tool_of(&self, tool: &str, name: &str) -> bool {
        let begins = format!("{}_", spelling(name));
        sent_names(tool).iter().any(|sent| sent.starts_with(&begins))
    }
}

/// The names OpenCode may have sent for `tool`: itself, and for
/// `mcp__<server>__<tool>`, `<server>_<tool>` at each `__` that may end the
/// server's name (a name may hold `__` too).
fn sent_names(tool: &str) -> Vec<String> {
    let mut names = vec![tool.to_owned()];
    if let Some(rest) = tool.strip_prefix("mcp__") {
        names.extend(
            rest.match_indices("__")
                .map(|(at, _)| format!("{}_{}", spelling(&rest[..at]), &rest[at + 2..])),
        );
    }
    names
}

/// `name` as OpenCode spells it in its tool names. JavaScript replaces each
/// UTF-16 unit, so a character outside the Basic Multilingual Plane becomes
/// two `_`.
pub(super) fn spelling(name: &str) -> String {
    name.chars()
        .flat_map(|c| {
            let kept = c.is_ascii_alphanumeric() || c == '_' || c == '-';
            let (with, count) = if kept { (c, 1) } else { ('_', c.len_utf16()) };
            std::iter::repeat_n(with, count)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_belongs_to_every_server_whose_spelling_begins_it() {
        assert!(Joined.tool_of("github_create_issue", "github"));
        assert!(!Joined.tool_of("github_create_issue", "git"));
        assert!(Joined.tool_of("my_db_query", "my.db"));
        // Both `files` and `files_read` begin `files_read_file`, sent or decided.
        for tool in ["files_read_file", "mcp__files_read__file"] {
            assert!(Joined.tool_of(tool, "files"), "{tool}");
            assert!(Joined.tool_of(tool, "files_read"), "{tool}");
        }
        assert!(!Joined.tool_of("mcp__other__file", "files"));
        assert_eq!(spelling("a\u{1F600}b"), "a__b");
    }

    /// OpenCode 2's `mcp.servers` and OpenCode 1's `mcp.<name>` in one file;
    /// a server of the old shape may be called `servers`.
    #[test]
    fn servers_of_both_shapes_are_read() {
        let named = |doc: Value| {
            let mut found: Vec<(String, String)> = OpenCodeJson
                .servers(&doc)
                .unwrap()
                .into_iter()
                .map(|s| (s.name, s.pointer))
                .collect();
            found.sort();
            found
        };
        let pair = |n: &str, p: &str| (n.to_owned(), p.to_owned());
        assert_eq!(
            named(serde_json::json!({"mcp": {
                "timeout": {"catalog": 5},
                "servers": {"db": {"type": "local", "command": ["db-mcp"]}},
                "old": {"type": "remote", "url": "https://example.invalid"},
            }})),
            [pair("db", "/mcp/servers/db"), pair("old", "/mcp/old")]
        );
        assert_eq!(
            named(serde_json::json!({"mcp": {"servers": {"type": "local", "command": ["x"]}}})),
            [pair("servers", "/mcp/servers")]
        );
    }
}
