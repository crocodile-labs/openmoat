//! Idempotent edits to a host's JSON hook file.
//!
//! Claude Code (`settings.json`) and Codex (`hooks.json`) share the shape
//! `{"hooks": {"<Event>": [{"matcher": …, "hooks": [{type, command, args, timeout}]}]}}`.
//! Our entries are recognised by their `args` (`guard --host <id>`), so re-running
//! `init` updates the binary path and matcher in place and never duplicates.
//! Unrelated settings are preserved byte-for-byte as JSON values.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde_json::{Map, Value, json};

use super::{HOOK_BACKUP, HookFormat, HookSpec, HostConfig};
use crate::home::{Home, write_private};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Unchanged,
    Updated,
    Installed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {
    Missing,
    Installed,
    /// Present but pointing at a different binary or matcher, or missing one event.
    Stale {
        command: String,
    },
    Unreadable(String),
}

pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    let path = &config.settings_path;
    let mut root = read_or_empty(path)?;
    let outcome = upsert_all(&mut root, config, binary)?;
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    super::back_up(home, path, HOOK_BACKUP)?;
    let text = serde_json::to_string_pretty(&root)? + "\n";
    write_private(path, text.as_bytes())?;
    Ok(outcome)
}

/// `current` (the text of the host's hook file, empty when there is none)
/// with OpenMoat's hooks in it, as [`install`] would write it; `None` when it
/// would not change. Writes nothing.
pub fn render(config: &HostConfig, binary: &Path, current: &str) -> Result<Option<String>> {
    let mut root = crate::sandbox::install::parse_json(current)?;
    if upsert_all(&mut root, config, binary)? == Outcome::Unchanged {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&root)? + "\n"))
}

fn upsert_all(root: &mut Value, config: &HostConfig, binary: &Path) -> Result<Outcome> {
    let mut outcome = Outcome::Unchanged;
    for spec in config.hooks {
        outcome = outcome.max(upsert(root, config, spec, binary)?);
    }
    Ok(outcome)
}

pub fn state(config: &HostConfig, binary: &Path) -> HookState {
    let path = &config.settings_path;
    if !path.exists() {
        return HookState::Missing;
    }
    let root = match read_or_empty(path) {
        Ok(v) => v,
        Err(e) => return HookState::Unreadable(format!("{e:#}")),
    };
    let mut found = 0;
    let mut stale_command = None;
    for spec in config.hooks {
        let ours = root
            .pointer(&format!("/hooks/{}", spec.event))
            .and_then(Value::as_array)
            .and_then(|entries| entries.iter().find(|e| is_ours(e, config)));
        match ours {
            Some(entry)
                if *entry == desired_entry(config, spec, binary, block(config, spec, entry)) =>
            {
                found += 1;
            }
            Some(entry) => {
                stale_command.get_or_insert_with(|| {
                    hook_binary(entry, config).unwrap_or_else(|| "?".into())
                });
            }
            None => {}
        }
    }
    match (found, stale_command) {
        (n, None) if n == config.hooks.len() => HookState::Installed,
        (0, None) => HookState::Missing,
        (_, Some(command)) => HookState::Stale { command },
        (_, None) => HookState::Stale {
            command: binary.to_string_lossy().into_owned(),
        },
    }
}

/// Whether our entry for `spec` carries `"onFailure": "block"`: it does when it
/// already has the key, so a shell without `claude` on `PATH` never takes the
/// key away, and otherwise when the host's version knows it.
fn block(config: &HostConfig, spec: &HookSpec, existing: &Value) -> bool {
    config.format == HookFormat::Nested
        && (has_block(existing) || (spec.block_on_failure && (config.blocks_on_failure)()))
}

/// [`block`] for an event with no entry of ours yet.
fn block_new(config: &HostConfig, spec: &HookSpec) -> bool {
    config.format == HookFormat::Nested && spec.block_on_failure && (config.blocks_on_failure)()
}

fn has_block(entry: &Value) -> bool {
    entry.pointer("/hooks/0/onFailure") == Some(&json!("block"))
}

fn desired_entry(config: &HostConfig, spec: &HookSpec, binary: &Path, block: bool) -> Value {
    match config.format {
        HookFormat::Nested => {
            let mut hook = json!({
                "type": "command",
                "command": binary.to_string_lossy(),
                "args": ["guard", "--host", config.host.id()],
                "timeout": spec.timeout,
            });
            if block {
                // Claude Code v2.1.295+: a hook that fails to start, crashes,
                // exits other than 0 or 2, or times out blocks the call as exit 2
                // does (<https://code.claude.com/docs/en/hooks>, "Block the
                // action when a hook fails"); without it the call runs.
                hook["onFailure"] = json!("block");
            }
            json!({ "matcher": spec.matcher, "hooks": [hook] })
        }
        HookFormat::Cursor => json!({
            "command": cursor_command(config, binary),
            "timeout": spec.timeout,
            "failClosed": true,
        }),
    }
}

/// Cursor takes one shell string; the binary path is quoted so spaces survive.
fn cursor_command(config: &HostConfig, binary: &Path) -> String {
    let path = binary.to_string_lossy().replace('"', "\\\"");
    format!("\"{path}\" guard --host {}", config.host.id())
}

/// The binary one of our entries runs, unquoted from Cursor's shell string.
fn hook_binary(entry: &Value, config: &HostConfig) -> Option<String> {
    if config.format == HookFormat::Cursor {
        let suffix = format!(" guard --host {}", config.host.id());
        let quoted = entry
            .get("command")?
            .as_str()?
            .trim_end()
            .strip_suffix(&suffix)?;
        return Some(quoted.trim().trim_matches('"').replace("\\\"", "\""));
    }
    entry
        .pointer("/hooks/0/command")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn is_ours(entry: &Value, config: &HostConfig) -> bool {
    if config.format == HookFormat::Cursor {
        let suffix = format!(" guard --host {}", config.host.id());
        return entry
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| c.trim_end().ends_with(&suffix));
    }
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|h| {
                h.get("args").and_then(Value::as_array).is_some_and(|args| {
                    let args: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
                    args == ["guard", "--host", config.host.id()]
                })
            })
        })
}

fn upsert(
    root: &mut Value,
    config: &HostConfig,
    spec: &HookSpec,
    binary: &Path,
) -> Result<Outcome> {
    let Value::Object(top) = root else {
        bail!("{} is not a JSON object", config.settings_path.display());
    };
    if config.format == HookFormat::Cursor {
        top.entry("version").or_insert_with(|| json!(1));
    }
    let hooks = top
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks else {
        bail!(
            "`hooks` in {} is not an object",
            config.settings_path.display()
        );
    };
    let entries = hooks
        .entry(spec.event)
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(entries) = entries else {
        bail!(
            "`hooks.{}` in {} is not an array",
            spec.event,
            config.settings_path.display()
        );
    };
    let Some(existing) = entries.iter_mut().find(|e| is_ours(e, config)) else {
        entries.push(desired_entry(config, spec, binary, block_new(config, spec)));
        return Ok(Outcome::Installed);
    };
    let desired = desired_entry(config, spec, binary, block(config, spec, existing));
    if *existing == desired {
        return Ok(Outcome::Unchanged);
    }
    *existing = desired;
    Ok(Outcome::Updated)
}

/// Whether one of our entries that should block a call when `moat guard`
/// fails ([`HookSpec::block_on_failure`]) has no `onFailure`.
pub fn lacks_on_failure(config: &HostConfig) -> bool {
    let Ok(root) = read_or_empty(&config.settings_path) else {
        return false;
    };
    config.format == HookFormat::Nested
        && config
            .hooks
            .iter()
            .filter(|spec| spec.block_on_failure)
            .filter_map(|spec| {
                root.pointer(&format!("/hooks/{}", spec.event))
                    .and_then(Value::as_array)
                    .and_then(|entries| entries.iter().find(|e| is_ours(e, config)))
            })
            .any(|entry| !has_block(entry))
}

/// The inverse of [`install`] on a parsed file: remove every entry of ours, then
/// the events and `hooks` object that leaves empty, and Cursor's `version` when
/// nothing else remains. Returns whether anything was removed.
pub fn remove(root: &mut Value, config: &HostConfig) -> bool {
    let Value::Object(top) = root else {
        return false;
    };
    let Some(Value::Object(hooks)) = top.get_mut("hooks") else {
        return false;
    };
    let mut removed = false;
    hooks.retain(|_, entries| {
        let Value::Array(list) = entries else {
            return true;
        };
        let before = list.len();
        list.retain(|e| !is_ours(e, config));
        removed |= list.len() != before;
        list.len() == before || !list.is_empty()
    });
    if removed && hooks.is_empty() {
        top.remove("hooks");
    }
    if removed && config.format == HookFormat::Cursor && top.len() == 1 {
        top.retain(|key, value| key != "version" || *value != json!(1));
    }
    removed
}

pub fn read_or_empty(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests;
