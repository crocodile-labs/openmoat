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
    let mut outcome = Outcome::Unchanged;
    for spec in config.hooks {
        outcome = outcome.max(upsert(&mut root, config, spec, binary)?);
    }
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    super::back_up(home, path, HOOK_BACKUP)?;
    let text = serde_json::to_string_pretty(&root)? + "\n";
    write_private(path, text.as_bytes())?;
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
            Some(entry) if *entry == desired_entry(config, spec, binary) => found += 1,
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

fn desired_entry(config: &HostConfig, spec: &HookSpec, binary: &Path) -> Value {
    match config.format {
        HookFormat::Nested => json!({
            "matcher": spec.matcher,
            "hooks": [{
                "type": "command",
                "command": binary.to_string_lossy(),
                "args": ["guard", "--host", config.host.id()],
                "timeout": spec.timeout,
            }]
        }),
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
    let desired = desired_entry(config, spec, binary);
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
    match entries.iter_mut().find(|e| is_ours(e, config)) {
        Some(existing) if *existing == desired => Ok(Outcome::Unchanged),
        Some(existing) => {
            *existing = desired;
            Ok(Outcome::Updated)
        }
        None => {
            entries.push(desired);
            Ok(Outcome::Installed)
        }
    }
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
mod tests {
    use super::*;
    use openmoat_hosts::Host;

    /// [`super::install`] with the state directory next to the hook file.
    fn install(config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
        super::install(&state_home(config), config, binary, dry_run)
    }

    fn state_home(config: &HostConfig) -> Home {
        Home::at(config.dir().join(".moat"))
    }

    const SPECS: &[HookSpec] = &[
        HookSpec {
            event: "PreToolUse",
            matcher: "Bash|Edit",
            timeout: 600,
        },
        HookSpec {
            event: "ConfigChange",
            matcher: "user_settings",
            timeout: 60,
        },
    ];

    fn config(dir: &Path) -> HostConfig {
        HostConfig {
            host: Host::ClaudeCode,
            settings_path: dir.join("settings.json"),
            hooks: SPECS,
            format: HookFormat::Nested,
        }
    }

    #[test]
    fn cursor_format_sets_version_fail_closed_and_a_quoted_command() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HostConfig {
            host: Host::Cursor,
            settings_path: dir.path().join("hooks.json"),
            hooks: &[HookSpec {
                event: "beforeShellExecution",
                matcher: "",
                timeout: 600,
            }],
            format: HookFormat::Cursor,
        };
        let binary = Path::new("/Applications/My Tools/moat");
        assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
        assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
        assert_eq!(state(&cfg, binary), HookState::Installed);
        let doc = root(&cfg);
        assert_eq!(doc["version"], 1);
        let entry = &doc["hooks"]["beforeShellExecution"][0];
        assert_eq!(
            entry["command"],
            "\"/Applications/My Tools/moat\" guard --host cursor"
        );
        assert_eq!(entry["failClosed"], true);
        assert_eq!(entry["timeout"], 600);
        assert!(entry.get("args").is_none());
        let moved = Path::new("/usr/local/bin/moat");
        assert_eq!(
            state(&cfg, moved),
            HookState::Stale {
                command: "/Applications/My Tools/moat".into()
            }
        );
        assert_eq!(install(&cfg, moved, false).unwrap(), Outcome::Updated);
        assert_eq!(
            root(&cfg)["hooks"]["beforeShellExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    fn root(cfg: &HostConfig) -> Value {
        serde_json::from_str(&fs::read_to_string(&cfg.settings_path).unwrap()).unwrap()
    }

    #[test]
    fn installs_every_event_idempotently_and_preserves_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        fs::write(
            &cfg.settings_path,
            r#"{"theme":"dark","hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[]}]}}"#,
        )
        .unwrap();
        let binary = Path::new("/opt/moat/bin/moat");

        assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
        assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
        assert_eq!(state(&cfg, binary), HookState::Installed);

        let moved = Path::new("/usr/local/bin/moat");
        assert_eq!(
            state(&cfg, moved),
            HookState::Stale {
                command: "/opt/moat/bin/moat".into()
            }
        );
        assert_eq!(install(&cfg, moved, false).unwrap(), Outcome::Updated);

        let root = root(&cfg);
        assert_eq!(root["theme"], "dark");
        assert_eq!(root["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
        let pre = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "no duplicates after three installs");
        assert_eq!(pre[0]["hooks"][0]["command"], "/usr/local/bin/moat");
        assert_eq!(pre[0]["hooks"][0]["timeout"], 600);
        let cfg_change = root["hooks"]["ConfigChange"].as_array().unwrap();
        assert_eq!(cfg_change.len(), 1);
        assert_eq!(cfg_change[0]["matcher"], "user_settings");
        assert_eq!(cfg_change[0]["hooks"][0]["timeout"], 60);
        assert!(
            cfg.settings_path
                .with_extension("json.moat-backup")
                .exists()
        );
    }

    #[test]
    fn install_keeps_the_first_backup_and_makes_a_deleted_one_again() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let original = r#"{"theme":"dark"}"#;
        fs::write(&cfg.settings_path, original).unwrap();
        let backup = cfg.settings_path.with_extension("json.moat-backup");

        install(&cfg, Path::new("/opt/moat/bin/moat"), false).unwrap();
        install(&cfg, Path::new("/usr/local/bin/moat"), false).unwrap();
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            original,
            "a later edit keeps the copy from before OpenMoat"
        );
        let recorded = super::super::Recorded::load(&state_home(&cfg)).unwrap();
        assert_eq!(recorded.backups, std::slice::from_ref(&backup));

        fs::remove_file(&backup).unwrap();
        let edited = fs::read_to_string(&cfg.settings_path).unwrap();
        install(&cfg, Path::new("/opt/moat/bin/moat"), false).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), edited);
    }

    #[test]
    fn remove_undoes_install_and_keeps_foreign_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let original = json!({"theme": "dark", "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "lint.sh"}]}
        ], "Stop": []}});
        fs::write(&cfg.settings_path, original.to_string()).unwrap();
        install(&cfg, Path::new("/x/moat"), false).unwrap();
        let mut doc = root(&cfg);
        assert!(remove(&mut doc, &cfg));
        assert_eq!(doc, original);
        assert!(!remove(&mut doc, &cfg), "nothing left to remove");

        let created = tempfile::tempdir().unwrap();
        let cursor = HostConfig {
            host: Host::Cursor,
            settings_path: created.path().join("hooks.json"),
            hooks: &SPECS[..1],
            format: HookFormat::Cursor,
        };
        install(&cursor, Path::new("/x/moat"), false).unwrap();
        let mut doc = root(&cursor);
        assert!(remove(&mut doc, &cursor));
        assert_eq!(doc, json!({}), "a file init created strips to nothing");
    }

    #[test]
    fn a_missing_event_entry_is_stale_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let binary = Path::new("/x/moat");
        install(&cfg, binary, false).unwrap();
        let mut root = root(&cfg);
        root["hooks"]
            .as_object_mut()
            .unwrap()
            .remove("ConfigChange");
        fs::write(&cfg.settings_path, root.to_string()).unwrap();
        assert!(matches!(state(&cfg, binary), HookState::Stale { .. }));
        assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
        assert_eq!(state(&cfg, binary), HookState::Installed);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        assert_eq!(
            install(&cfg, Path::new("/x/moat"), true).unwrap(),
            Outcome::Installed
        );
        assert!(!cfg.settings_path.exists());
        assert_eq!(state(&cfg, Path::new("/x/moat")), HookState::Missing);
    }

    #[test]
    fn foreign_entries_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        fs::write(
            &cfg.settings_path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"lint.sh"}]}]}}"#,
        )
        .unwrap();
        install(&cfg, Path::new("/x/moat"), false).unwrap();
        let pre = root(&cfg)["hooks"]["PreToolUse"].clone();
        let pre = pre.as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "lint.sh");
    }

    #[test]
    fn malformed_files_are_reported_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        fs::write(&cfg.settings_path, "{ not json").unwrap();
        assert!(install(&cfg, Path::new("/x/moat"), false).is_err());
        assert!(matches!(
            state(&cfg, Path::new("/x/moat")),
            HookState::Unreadable(_)
        ));
        assert_eq!(
            fs::read_to_string(&cfg.settings_path).unwrap(),
            "{ not json"
        );
    }
}
