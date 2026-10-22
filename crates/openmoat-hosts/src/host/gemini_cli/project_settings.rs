//! Gemini CLI's `settings.json` keys that turn OpenMoat's hook off or run
//! programs (`@google/gemini-cli` 0.65.0 `config/settingsSchema.ts`,
//! `hooks/hookRegistry.ts`): `hooksConfig.enabled: false` turns every hook
//! off, and `hooksConfig.disabled`, joined across the user's and a trusted
//! project's file, turns off each hook it names by `name` or `command`.

use serde_json::{Map, Value};

use crate::contract::{SettingsFile, SettingsReader, set};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root)
    }

    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String> {
        switched_off(file.root)
    }
}

/// The `name` OpenMoat's entry carries (`install/hook_file`).
const HOOK_NAME: &str = "openmoat";

/// What in `root` turns OpenMoat's `BeforeTool` hook off.
pub(super) fn switched_off(root: &Map<String, Value>) -> Vec<String> {
    let mut found = Vec::new();
    let config = root.get("hooksConfig");
    if config
        .and_then(|c| c.get("enabled"))
        .is_some_and(|v| v != &Value::Bool(true))
    {
        found.push("`hooksConfig.enabled` turns off every hook, OpenMoat's included".to_owned());
    }
    if let Some(disabled) = config.and_then(|c| c.get("disabled")) {
        let names_ours = |v: &Value| {
            v.as_str()
                .is_none_or(|s| s == HOOK_NAME || s.contains("openmoat"))
        };
        let ours = match disabled {
            Value::Array(items) => items.iter().any(names_ours),
            Value::Null => false,
            other => names_ours(other),
        };
        if ours {
            found.push("`hooksConfig.disabled` turns OpenMoat's hook off".to_owned());
        }
    }
    found
}

/// What a project's `settings.json` sets that turns OpenMoat off, runs a
/// program or adds a hook. Its MCP servers are named too: Gemini CLI starts
/// them when the session starts, though their tool calls are held by their
/// pins (ADR-026).
pub(super) fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = switched_off(root);
    if set(root.get("hooks")) {
        found.push(
            "`hooks` adds hooks that run commands and can rewrite a call's arguments".to_owned(),
        );
    }
    for key in ["discoveryCommand", "callCommand"] {
        if set(root.get("tools").and_then(|t| t.get(key))) {
            found.push(format!("`tools.{key}` sets a command Gemini CLI runs"));
        }
    }
    if set(root.get("mcpServers")) {
        found.push(
            "`mcpServers` starts MCP servers, which runs their commands (OpenMoat still holds \
             back their tool calls)"
                .to_owned(),
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn off(value: &Value) -> Vec<String> {
        switched_off(value.as_object().unwrap())
    }

    #[test]
    fn hooks_turned_off_or_openmoat_disabled_are_named() {
        assert_eq!(off(&json!({"hooksConfig": {"enabled": false}})).len(), 1);
        assert_eq!(
            off(&json!({"hooksConfig": {"disabled": ["openmoat"]}})).len(),
            1
        );
        let command = "'/opt/bin/openmoat' guard --host gemini-cli";
        assert_eq!(
            off(&json!({"hooksConfig": {"disabled": [command]}})).len(),
            1
        );
        // A value OpenMoat cannot read is taken as naming it.
        assert_eq!(off(&json!({"hooksConfig": {"disabled": [1]}})).len(), 1);
        for fine in [
            json!({}),
            json!({"hooksConfig": {"enabled": true, "disabled": ["lint"]}}),
            json!({"hooks": {"BeforeTool": []}, "model": {"name": "x"}}),
        ] {
            assert!(off(&fine).is_empty(), "{fine}");
        }
    }

    #[test]
    fn a_project_hook_command_or_server_is_named() {
        let all = findings(
            json!({
                "hooksConfig": {"enabled": false},
                "hooks": {"BeforeTool": [{"matcher": "*", "hooks": []}]},
                "tools": {"discoveryCommand": "./tools.sh", "callCommand": "./call.sh"},
                "mcpServers": {"x": {"command": "x"}},
            })
            .as_object()
            .unwrap(),
        );
        assert_eq!(all.len(), 5, "{all:?}");
        let quiet = findings(
            json!({"ui": {"theme": "x"}, "hooks": {}})
                .as_object()
                .unwrap(),
        );
        assert!(quiet.is_empty(), "{quiet:?}");
    }
}
