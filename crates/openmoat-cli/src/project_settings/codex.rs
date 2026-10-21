//! Codex's `config.toml` and `hooks.json` keys that turn OpenMoat's hook off or
//! run programs (<https://learn.chatgpt.com/docs/hooks>, checked 2026-10-21):
//! hooks are on by default and `[features] hooks = false` (or its deprecated
//! alias `codex_hooks`) turns every one off; a trusted project's `.codex/`
//! layer adds its own `hooks.json` and inline `[hooks]`, which run beside
//! OpenMoat's. The file is read as JSON (`toml_to_json`).

use serde_json::{Map, Value};

use super::set;

/// What in `root` turns every Codex hook off, OpenMoat's included.
pub(super) fn switched_off(root: &Map<String, Value>) -> Vec<String> {
    let features = root.get("features");
    ["hooks", "codex_hooks"]
        .into_iter()
        .filter(|key| {
            features
                .and_then(|f| f.get(*key))
                .is_some_and(|v| v != &Value::Bool(true))
        })
        .map(|key| format!("`features.{key}` turns off every hook, OpenMoat's included"))
        .collect()
}

/// What a trusted project's `.codex/config.toml` or `.codex/hooks.json` sets
/// that turns OpenMoat off, adds a hook, runs a program, starts MCP servers or
/// changes the sandbox OpenMoat configures.
pub(super) fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = switched_off(root);
    if set(root.get("hooks")) {
        found.push("`hooks` adds hooks that run commands".to_owned());
    }
    if set(root.get("notify")) {
        found.push("`notify` sets a command Codex runs after each turn".to_owned());
    }
    if set(root.get("mcp_servers")) {
        found.push(
            "`mcp_servers` starts MCP servers, which runs their commands (OpenMoat still holds \
             back their tool calls)"
                .to_owned(),
        );
    }
    for key in ["sandbox_mode", "default_permissions", "permissions"] {
        if set(root.get(key)) {
            found.push(format!(
                "`{key}` changes the sandbox Codex runs commands in"
            ));
        }
    }
    if set(root.get("model_providers")) {
        found.push("`model_providers` sends the session to another model endpoint".to_owned());
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn hooks_turned_off_by_either_key_are_named() {
        let off = |v: Value| switched_off(v.as_object().unwrap()).len();
        assert_eq!(off(json!({"features": {"hooks": false}})), 1);
        assert_eq!(off(json!({"features": {"codex_hooks": false}})), 1);
        assert_eq!(
            off(json!({"features": {"hooks": true, "network_proxy": true}})),
            0
        );
        assert_eq!(off(json!({"model": "gpt-5"})), 0);
    }

    #[test]
    fn a_project_layer_that_adds_hooks_or_programs_is_named() {
        let all = findings(
            json!({
                "features": {"hooks": false},
                "hooks": {"PreToolUse": [{"hooks": []}]},
                "notify": ["./notify.sh"],
                "mcp_servers": {"x": {"command": "x"}},
                "sandbox_mode": "danger-full-access",
                "model_providers": {"p": {"base_url": "https://x"}},
            })
            .as_object()
            .unwrap(),
        );
        assert_eq!(all.len(), 6, "{all:?}");
        assert!(findings(json!({"model": "x", "hooks": {}}).as_object().unwrap()).is_empty());
    }
}
