//! A project's `.agents/` hook and MCP files, and the person's `settings.json`.
//!
//! A hook file is `{ "<name>": { "enabled": bool, "<event>": [...] } }`. How a
//! project's file merges with the person's is not documented, so a project
//! entry named as OpenMoat's that is not `enabled` is taken as turning it off,
//! and every other named hook as one that can rewrite a call's arguments.

use serde_json::{Map, Value};

use crate::contract::{PluginDir, SettingsFile, SettingsReader, set};

/// OpenMoat's entry's name and the plugin name a project cannot reuse.
const NAME: &str = super::hook_file::NAME;

/// A project's plugins, each with an optional `hooks.json` at its root
/// (`/docs/settings`). Whether one named `openmoat` replaces OpenMoat's own
/// hook is not documented, so it is reported as if it did.
pub(super) const PROJECT_PLUGINS: PluginDir = PluginDir {
    path: ".agents/plugins",
    hook_file: "hooks.json",
    own: NAME,
};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root)
    }

    /// `~/.gemini/antigravity-cli/settings.json` holds no hook settings
    /// ("the CLI keeps a `hooks` key there but never loads it"); a project's
    /// hook file can name OpenMoat's entry.
    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String> {
        switched_off(file.root)
    }
}

/// What in `root` turns OpenMoat's named hook off.
pub(super) fn switched_off(root: &Map<String, Value>) -> Vec<String> {
    let enabled = root.get(NAME).and_then(|hook| hook.get("enabled"));
    if enabled.is_some_and(|v| *v != Value::Bool(true)) {
        return vec![format!("`{NAME}.enabled` turns OpenMoat's hook off")];
    }
    Vec::new()
}

/// What a project's `hooks.json` or `mcp_config.json` sets: OpenMoat's entry
/// turned off, other hooks, or MCP servers. A top-level `mcpServers` is the
/// MCP file's only key of interest.
pub(super) fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = switched_off(root);
    for (name, value) in root {
        if name == "mcpServers" {
            if set(Some(value)) {
                found.push(
                    "`mcpServers` starts MCP servers, which runs their commands (OpenMoat still \
                     holds back their tool calls)"
                        .to_owned(),
                );
            }
        } else if value.is_object() && name != NAME {
            found.push(format!(
                "`{name}` adds a hook that runs commands and can rewrite a call's arguments"
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn of(value: &Value) -> Vec<String> {
        findings(value.as_object().unwrap())
    }

    #[test]
    fn a_project_entry_that_turns_openmoat_off_is_named() {
        assert_eq!(of(&json!({"openmoat": {"enabled": false}})).len(), 1);
        // A value other than `true` is read as off, as the host could.
        assert_eq!(of(&json!({"openmoat": {"enabled": "no"}})).len(), 1);
        assert_eq!(of(&json!({"openmoat": {"enabled": true}})).len(), 0);
    }

    #[test]
    fn other_hooks_and_servers_are_named() {
        let all = of(&json!({
            "lint": {"PreToolUse": []},
            "mcpServers": {"x": {"command": "x"}},
        }));
        assert_eq!(all.len(), 2, "{all:?}");
        assert_eq!(of(&json!({"mcpServers": {}})).len(), 0);
    }
}
