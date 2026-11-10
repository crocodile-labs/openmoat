//! goose's extensions (`extensions` in `config.yaml`) and how it names their
//! tools.

use serde_json::Value;

use crate::contract::{McpCommandForm, McpNames, McpReader, McpServer, McpSyntax, escape, server};

/// `extensions: {<key>: {enabled, type, name, cmd, args, envs, uri, …}}` in
/// YAML (`ExtensionEntry` in `config/extensions.rs`, `ExtensionConfig` in
/// `agents/extension.rs`, v1.57.0). Every entry is pinned without `enabled`,
/// which goose's own settings switch on and off and which changes nothing
/// the extension runs.
#[derive(Debug)]
pub(crate) struct Extensions;

impl McpReader for Extensions {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Yaml
    }

    fn command_form(&self) -> McpCommandForm {
        McpCommandForm::CmdArgs
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        match doc.get("extensions") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Object(entries)) => Ok(entries
                .iter()
                .map(|(name, entry)| {
                    let mut entry = entry.clone();
                    if let Value::Object(fields) = &mut entry {
                        fields.remove("enabled");
                    }
                    server(format!("/extensions/{}", escape(name)), name, &entry)
                })
                .collect()),
            Some(_) => Err("`extensions` is not a mapping of extensions".to_owned()),
        }
    }
}

/// `<key>__<tool>`, recorded as `mcp__<key>__<tool>`, where the key is the
/// extension's name with whitespace dropped, every character but ASCII
/// letters, digits, `_` and `-` as `_`, lowercased (`name_to_key`). The CLI's
/// own check covers the name as written.
#[derive(Debug)]
pub(crate) struct GooseNames;

impl McpNames for GooseNames {
    fn tool_of(&self, tool: &str, server: &str) -> bool {
        tool.starts_with(&format!("mcp__{}__", key(server)))
    }
}

/// goose's key for an extension named `name`.
pub(super) fn key(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extensions_are_pinned_without_enabled() {
        let doc = json!({ "extensions": {
            "github": { "enabled": true, "type": "stdio", "name": "GitHub", "cmd": "npx" },
        }});
        let servers = Extensions.servers(&doc).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].pointer, "/extensions/github");
        assert_eq!(servers[0].entry, json!({ "type": "stdio", "name": "GitHub", "cmd": "npx" }));
        assert_eq!(Extensions.servers(&json!({})).unwrap(), Vec::<McpServer>::new());
        assert!(Extensions.servers(&json!({ "extensions": [1] })).is_err());
    }

    #[test]
    fn tool_names_follow_the_extension_key() {
        assert!(GooseNames.tool_of("mcp__mytools__run", "My Tools"));
        assert!(GooseNames.tool_of("mcp__a_b__x", "a.b"));
        assert!(!GooseNames.tool_of("mcp__other__run", "my-tools"));
        assert_eq!(key("Big Server!"), "bigserver_");
    }
}
