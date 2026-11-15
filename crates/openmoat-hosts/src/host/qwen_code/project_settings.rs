//! Qwen Code's `settings.json` keys that turn OpenMoat's hook off or run
//! programs (the hooks page and the settings reference): `disableAllHooks:
//! true` loads no hook at all; a project's `hooks` run once the person
//! approves them or trusts the folder, and can rewrite a call's arguments
//! (`updatedInput`); `mcpServers` starts servers.

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

/// What in `root` turns OpenMoat's `PreToolUse` hook off. A value that is
/// not `false` is taken as turning hooks off: Qwen Code's reading of one was
/// not checked.
fn switched_off(root: &Map<String, Value>) -> Vec<String> {
    match root.get("disableAllHooks") {
        None | Some(Value::Bool(false) | Value::Null) => Vec::new(),
        Some(_) => vec!["`disableAllHooks` turns off every hook, OpenMoat's included".to_owned()],
    }
}

/// What a project's `settings.json` sets that turns OpenMoat off, adds a hook
/// or starts a server.
fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = switched_off(root);
    if set(root.get("hooks")) {
        found.push(
            "`hooks` adds hooks that run commands and can rewrite a call's arguments".to_owned(),
        );
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

    fn of(value: &Value) -> (Vec<String>, Vec<String>) {
        let root = value.as_object().unwrap();
        (switched_off(root), findings(root))
    }

    #[test]
    fn disable_all_hooks_is_named_and_false_is_not() {
        assert_eq!(of(&json!({"disableAllHooks": true})).0.len(), 1);
        assert_eq!(of(&json!({"disableAllHooks": "yes"})).0.len(), 1);
        for fine in [json!({}), json!({"disableAllHooks": false}), json!({"ui": {}})] {
            assert!(of(&fine).0.is_empty(), "{fine}");
            assert!(of(&fine).1.is_empty(), "{fine}");
        }
    }

    #[test]
    fn a_project_hook_or_server_is_named() {
        let (off, all) = of(&json!({
            "disableAllHooks": true,
            "hooks": {"PreToolUse": [{"matcher": "*", "hooks": []}]},
            "mcpServers": {"x": {"command": "x"}},
        }));
        assert_eq!(off.len(), 1);
        assert_eq!(all.len(), 3, "{all:?}");
    }
}
