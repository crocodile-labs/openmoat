//! Mirrors rust-v0.166.0 discovery.rs `hook_hash` and config/fingerprint.rs;
//! the event labels (`pre_tool_use`, `post_tool_use`) are `hook_event_key_label`
//! in `codex-rs/hooks/src/lib.rs`.
//! This is advisory only: Codex owns its hash format, so a mismatch must never
//! block a call, installation, upgrade, or status/doctor's success exit code.

use serde_json::{Value, json};

use crate::{HookFile, HookTrust};

#[derive(Debug)]
pub(super) struct Codex;

impl HookTrust for Codex {
    fn toml_file(&self) -> &'static str {
        "config.toml"
    }

    fn warning(
        &self,
        hooks: &Value,
        config: &Value,
        source: &str,
        sha256: fn(&[u8]) -> String,
    ) -> Option<String> {
        // `PreToolUse` must be there; `PostToolUse` (ADR-063) is checked
        // when present, since an install without it is reported stale.
        let approved = |event: &str, name: &str| -> Option<bool> {
            let groups = hooks.get("hooks")?.get(event)?.as_array()?;
            let (index, group) = groups
                .iter()
                .enumerate()
                .find(|(_, g)| super::hook_file::Codex.is_ours(g, "codex"))?;
            let handler = group.pointer("/hooks/0")?;
            let hash = hash(name, group, handler, sha256)?;
            let key = format!("{source}:{name}:{index}:0");
            let state = config.get("hooks")?.get("state")?.get(&key)?;
            Some(
                state.get("enabled").and_then(Value::as_bool) != Some(false)
                    && state.get("trusted_hash")?.as_str()? == hash,
            )
        };
        let post_present = hooks
            .pointer("/hooks/PostToolUse")
            .and_then(Value::as_array)
            .is_some_and(|groups| {
                groups
                    .iter()
                    .any(|g| super::hook_file::Codex.is_ours(g, "codex"))
            });
        let trusted = approved("PreToolUse", "pre_tool_use") == Some(true)
            && (!post_present || approved("PostToolUse", "post_tool_use") == Some(true));
        (!trusted).then(|| {
            "installed but not trusted (or disabled) in Codex; open Codex, run /hooks and trust the OpenMoat hooks".to_owned()
        })
    }
}

/// Codex's hash of one hook: its event's snake-case `name`, the group's
/// matcher and the handler's fields as Codex normalises them.
fn hash(
    name: &str,
    group: &Value,
    handler: &Value,
    sha256: fn(&[u8]) -> String,
) -> Option<String> {
    let command = if cfg!(windows) {
        "commandWindows"
    } else {
        "command"
    };
    let identity = json!({
        "event_name": name, "matcher": group.get("matcher")?,
        "hooks": [{"type": "command", "command": handler.get(command)?,
            "timeout": handler.get("timeout")?, "async": false,
            "statusMessage": handler.get("statusMessage")?}],
    });
    Some(format!(
        "sha256:{}",
        sha256(&serde_json::to_vec(&identity).ok()?)
    ))
}

#[cfg(test)]
mod tests;
