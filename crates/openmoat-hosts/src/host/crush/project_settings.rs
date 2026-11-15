//! What a Crush `crush.json` sets that OpenMoat warns about. No key turns
//! hooks off: the hooks of every file Crush loads are appended to one another
//! (`jsons.Merge` in `internal/config/load.go`). A project's `hooks` run
//! beside OpenMoat's and can rewrite a call's arguments (`updated_input`),
//! its `mcp` servers start with the session, and `permissions.allowed_tools`
//! skips Crush's own prompts.

use serde_json::{Map, Value};

use crate::contract::{SettingsFile, SettingsReader, set};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root)
    }

    /// Nothing in a `crush.json` turns OpenMoat's hook off.
    fn switched_off(&self, _file: &SettingsFile<'_>) -> Vec<String> {
        Vec::new()
    }
}

fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = Vec::new();
    if set(root.get("hooks")) {
        found.push(
            "`hooks` adds hooks that run commands and can rewrite a call's arguments".to_owned(),
        );
    }
    if set(root.get("mcp")) {
        found.push(
            "`mcp` starts MCP servers, which runs their commands (OpenMoat still holds back \
             their tool calls)"
                .to_owned(),
        );
    }
    if set(root.get("permissions").and_then(|p| p.get("allowed_tools"))) {
        found.push(
            "`permissions.allowed_tools` runs those tools without Crush's own prompt".to_owned(),
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_project_hook_server_or_allowed_tool_is_named() {
        let all = findings(
            json!({
                "hooks": {"PreToolUse": [{"command": "./x.sh"}]},
                "mcp": {"x": {"type": "stdio", "command": "x"}},
                "permissions": {"allowed_tools": ["bash"]},
            })
            .as_object()
            .unwrap(),
        );
        assert_eq!(all.len(), 3, "{all:?}");
        let quiet = findings(json!({"options": {"debug": true}}).as_object().unwrap());
        assert!(quiet.is_empty(), "{quiet:?}");
    }
}
