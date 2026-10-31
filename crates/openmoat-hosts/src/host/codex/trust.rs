//! Mirrors rust-v0.166.0 discovery.rs `hook_hash` and config/fingerprint.rs.
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
        let approved = || -> Option<bool> {
            let groups = hooks.pointer("/hooks/PreToolUse")?.as_array()?;
            let (index, group) = groups
                .iter()
                .enumerate()
                .find(|(_, g)| super::hook_file::Codex.is_ours(g, "codex"))?;
            let handler = group.pointer("/hooks/0")?;
            let hash = hash(group, handler, sha256)?;
            let key = format!("{source}:pre_tool_use:{index}:0");
            let state = config.get("hooks")?.get("state")?.get(&key)?;
            Some(
                state.get("enabled").and_then(Value::as_bool) != Some(false)
                    && state.get("trusted_hash")?.as_str()? == hash,
            )
        };
        (approved() != Some(true)).then(|| {
            "installed but not trusted (or disabled) in Codex; open Codex, run /hooks and trust the OpenMoat hook".to_owned()
        })
    }
}

fn hash(group: &Value, handler: &Value, sha256: fn(&[u8]) -> String) -> Option<String> {
    let command = if cfg!(windows) {
        "commandWindows"
    } else {
        "command"
    };
    let identity = json!({
        "event_name": "pre_tool_use", "matcher": group.get("matcher")?,
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
