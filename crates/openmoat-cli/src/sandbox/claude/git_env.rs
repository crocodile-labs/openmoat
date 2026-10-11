//! `safe.bareRepository=explicit` in the settings' `env` block, which Claude
//! Code copies into its own environment and so into every command it starts,
//! sandboxed or not. A value there replaces the same variable exported in the
//! shell Claude Code starts from, so entries from the shell are not kept; those
//! already in the block are.

use anyhow::Result;
use serde_json::{Map, Value};

use super::settings::object_at;
use crate::sandbox::git_env::{self, Change};

fn lookup(env: Option<&Map<String, Value>>) -> impl Fn(&str) -> Option<String> {
    move |var| {
        env.and_then(|e| e.get(var))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

/// Append the entry to `env` unless it already applies.
pub(super) fn apply(top: &mut Map<String, Value>) -> Result<()> {
    let env = object_at(top, "env")?;
    let added = git_env::add(&lookup(Some(env)))?;
    for (var, value) in added {
        env.insert(var, Value::String(value));
    }
    Ok(())
}

/// Whether `env` in `root` makes git use only named bare repositories.
pub(super) fn in_sync(root: &Value) -> bool {
    git_env::present(&lookup(root.get("env").and_then(Value::as_object)))
}

/// Remove the entry, and `env` when that empties it. Returns whether anything changed.
pub(super) fn remove(top: &mut Map<String, Value>) -> bool {
    let Some(Value::Object(env)) = top.get_mut("env") else {
        return false;
    };
    let changes = git_env::remove(&lookup(Some(env)));
    for change in &changes {
        match change {
            Change::Set(var, value) => env.insert(var.clone(), Value::String(value.clone())),
            Change::Unset(var) => env.remove(var),
        };
    }
    if env.is_empty() {
        top.remove("env");
    }
    !changes.is_empty()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn appends_after_the_users_entries_and_removes_only_its_own() {
        let user = json!({
            "env": {
                "DISABLE_AUTO_COMPACT": "1",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "user.name",
                "GIT_CONFIG_VALUE_0": "me"
            }
        });
        let mut root = user.clone();
        let top = root.as_object_mut().unwrap();
        apply(top).unwrap();
        assert_eq!(root["env"]["GIT_CONFIG_COUNT"], "2");
        assert_eq!(root["env"]["GIT_CONFIG_KEY_1"], "safe.bareRepository");
        assert_eq!(root["env"]["GIT_CONFIG_VALUE_1"], "explicit");
        assert!(in_sync(&root));
        let top = root.as_object_mut().unwrap();
        assert!(remove(top));
        assert!(!remove(top));
        assert_eq!(root, user);
    }

    #[test]
    fn the_settings_get_it_with_the_sandbox_and_lose_it_on_uninstall() {
        let generated = super::super::tests::generated(openmoat_core::DEFAULT_POLICY);
        let mut root = json!({ "model": "opus" });
        let mut owned = Vec::new();
        super::super::apply(&mut root, &generated, &mut owned).unwrap();
        assert_eq!(root["env"]["GIT_CONFIG_VALUE_0"], "explicit");
        assert!(super::super::in_sync(&root, &generated, &owned));
        root["env"]["GIT_CONFIG_COUNT"] = json!("0");
        assert!(!super::super::in_sync(&root, &generated, &owned));
        root["env"]["GIT_CONFIG_COUNT"] = json!("1");
        assert!(super::super::remove(&mut root, &owned));
        assert_eq!(root, json!({ "model": "opus" }));
    }
}
