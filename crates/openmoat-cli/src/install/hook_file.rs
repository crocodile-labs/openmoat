//! Idempotent edits to a host's JSON hook file.
//!
//! The layouts whose entries sit among the person's own (Claude Code, Codex,
//! Cursor, GitHub Copilot CLI, Gemini CLI) are pure code in the hosts crate
//! ([`openmoat_hosts::HookFile`]); this module reads, backs up and writes the
//! file. A file OpenMoat owns whole (pi's extension, OpenCode's plugin) is written by [`owned`],
//! a plugin configuration (OpenClaw's `openclaw.json`) by [`plugin_config`], a
//! YAML file (Hermes Agent's `config.yaml`) by [`yaml`]; the host's spec says
//! which ([`HookLayout`]).

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::HookFileState;
use serde_json::{Map, Value};

use super::{HOOK_BACKUP, HookLayout, HostConfig, json5_file, owned, plugin_config, yaml};
use crate::home::{Home, KeepMode, write_like};

pub use openmoat_hosts::HookOutcome as Outcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {
    Missing,
    Installed,
    /// Present but pointing at a different binary or matcher, or missing one event.
    Stale {
        command: String,
    },
    Unreadable(String),
    /// Installed, but the host's consent file does not approve it, so the
    /// host skips it where it cannot prompt; the reason says so.
    Unapproved(String),
    /// An entry of ours lacks the host's fail-closed key set to `true`
    /// ([`openmoat_hosts::HookFile::fail_closed_key`]), so the host runs a
    /// call whose hook failed to start, crashed or timed out; the reason says so.
    FailsOpen(String),
    /// The layout's switch for its section ([`openmoat_hosts::HookFile::section_switch`])
    /// is not `true`, so the host never runs our entries; the reason says so.
    TurnedOff(String),
}

/// [`HookState::FailsOpen`] for `config` when an entry of ours in `root`
/// lacks the layout's fail-closed key, otherwise `state`.
pub fn unless_fails_open(
    state: HookState,
    config: &HostConfig,
    layout: &'static dyn openmoat_hosts::HookFile,
    root: &Value,
) -> HookState {
    if matches!(state, HookState::Missing | HookState::Unreadable(_)) {
        return state;
    }
    if layout.turned_off(root) {
        return HookState::TurnedOff(format!(
            "OpenMoat's hook in {} is switched off (`enabled` under `{}` is not `true`), so {} \
             never runs it; run `openmoat init`",
            config.settings_path.display(),
            layout.section(),
            config.host.display_name()
        ));
    }
    match layout.fails_open(root, config.host.id(), config.hooks) {
        Some(key) => HookState::FailsOpen(format!(
            "OpenMoat's hook entry in {} lacks `{key}: true`, so {} runs a call when the \
             hook cannot start, crashes or times out; run `openmoat init`",
            config.settings_path.display(),
            config.host.display_name()
        )),
        None => state,
    }
}

pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    // A file OpenMoat owns whole is not JSON, nor is a YAML one.
    match config.layout {
        HookLayout::Owned(file) | HookLayout::Script(file) => {
            return owned::install(home, config, file, binary, dry_run);
        }
        HookLayout::Yaml(layout) => return yaml::install(home, config, layout, binary, dry_run),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    let path = &config.settings_path;
    let mut root = read_host(config)?;
    let edited = upsert_all(&mut root, config, binary)?;
    let plugin = match config.layout {
        HookLayout::Plugin(plugin) => Some(plugin),
        HookLayout::Entries(_)
        | HookLayout::Yaml(_)
        | HookLayout::Owned(_)
        | HookLayout::Script(_) => None,
    };
    if edited != Outcome::Unchanged && plugin.is_some() {
        json5_file::read_for_edit(path)?;
    }
    // The plugin is a file of its own in the configuration directory.
    let plugin = plugin.filter(|plugin| !plugin_config::plugin_current(config, *plugin, binary));
    let outcome = if plugin.is_some() {
        edited.max(Outcome::Updated)
    } else {
        edited
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if let Some(plugin) = plugin {
        plugin_config::write_plugin(config, plugin, binary)?;
    }
    if edited != Outcome::Unchanged {
        super::back_up(home, path, HOOK_BACKUP)?;
        let text = serde_json::to_string_pretty(&root)? + "\n";
        write_like(path, text.as_bytes(), path, KeepMode::NotWritableByOthers)?;
    }
    Ok(outcome)
}

/// `current` (the text of the host's hook file, empty when there is none)
/// with OpenMoat's hooks in it, as [`install`] would write it; `None` when it
/// would not change. Writes nothing.
pub fn render(config: &HostConfig, binary: &Path, current: &str) -> Result<Option<String>> {
    match config.layout {
        HookLayout::Owned(file) | HookLayout::Script(file) => {
            return owned::render(config, file, binary, current);
        }
        HookLayout::Yaml(layout) => return yaml::render(config, layout, binary, current),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    if let HookLayout::Plugin(_) = config.layout {
        let parsed = json5_file::parse_or_empty(current)
            .with_context(|| format!("parsing {}", config.settings_path.display()))?;
        let mut root = parsed.value.clone();
        if upsert_all(&mut root, config, binary)? == Outcome::Unchanged {
            return Ok(None);
        }
        json5_file::refuse_comments(&parsed, &config.settings_path)?;
        return Ok(Some(serde_json::to_string_pretty(&root)? + "\n"));
    }
    let mut root = crate::sandbox::install::parse_json(current)?;
    if upsert_all(&mut root, config, binary)? == Outcome::Unchanged {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&root)? + "\n"))
}

fn upsert_all(root: &mut Value, config: &HostConfig, binary: &Path) -> Result<Outcome> {
    if let HookLayout::Plugin(plugin) = config.layout {
        return plugin_config::upsert(root, config, plugin);
    }
    let Some(layout) = config.layout.entries() else {
        bail!("{} is not a JSON hook file", config.settings_path.display());
    };
    layout
        .upsert(
            root,
            &config.settings_path.display().to_string(),
            config.host.id(),
            config.hooks,
            &config.guard(binary),
            config.blocks_on_failure,
        )
        .map_err(anyhow::Error::new)
}

/// The hook's state for `binary`. A hook that runs `binary`'s `moat` alias
/// counts as installed: hooks written before the rename keep working through
/// it, and `init` rewrites them to `binary` (an edit compares exactly).
pub fn state(config: &HostConfig, binary: &Path) -> HookState {
    let exact = state_for(config, binary);
    if exact == HookState::Installed {
        return exact;
    }
    match super::alias_of(binary) {
        Some(alias) if state_for(config, &alias) == HookState::Installed => HookState::Installed,
        _ => exact,
    }
}

/// Whether the installed hook runs `binary`'s `moat` alias, not `binary`.
pub fn runs_alias(config: &HostConfig, binary: &Path) -> bool {
    state_for(config, binary) != HookState::Installed
        && super::alias_of(binary)
            .is_some_and(|alias| state_for(config, &alias) == HookState::Installed)
}

fn state_for(config: &HostConfig, binary: &Path) -> HookState {
    let path = &config.settings_path;
    if !path.exists() {
        return HookState::Missing;
    }
    match config.layout {
        HookLayout::Owned(file) | HookLayout::Script(file) => {
            return owned::state(config, file, binary);
        }
        HookLayout::Yaml(layout) => return yaml::state(config, layout, binary),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    let root = match read_host(config) {
        Ok(v) => v,
        Err(e) => return HookState::Unreadable(format!("{e:#}")),
    };
    let layout = match config.layout {
        HookLayout::Plugin(plugin) => return plugin_config::state(config, plugin, binary, &root),
        HookLayout::Owned(_) | HookLayout::Script(_) | HookLayout::Yaml(_) => {
            return HookState::Missing;
        }
        HookLayout::Entries(layout) => layout,
    };
    let id = config.host.id();
    let guard = config.guard(binary);
    let state = match layout.state(&root, id, config.hooks, &guard, config.blocks_on_failure) {
        HookFileState::Missing => HookState::Missing,
        HookFileState::Installed => HookState::Installed,
        HookFileState::Stale { command } => HookState::Stale { command },
    };
    unless_fails_open(state, config, layout, &root)
}

/// Whether one of our entries that should block a call when `moat guard`
/// fails ([`super::HookSpec::block_on_failure`]) has no `onFailure`.
pub fn lacks_on_failure(config: &HostConfig) -> bool {
    let Ok(root) = read_or_empty(&config.settings_path) else {
        return false;
    };
    config
        .layout
        .entries()
        .is_some_and(|l| l.lacks_on_failure(&root, config.host.id(), config.hooks))
}

/// The inverse of [`install`] on a parsed file: remove every entry of ours, then
/// the events and `hooks` object that leaves empty, and Cursor's `version` when
/// nothing else remains. Returns whether anything was removed.
pub fn remove(root: &mut Value, config: &HostConfig) -> bool {
    match config.layout {
        HookLayout::Plugin(plugin) => plugin.remove(root),
        HookLayout::Entries(layout) | HookLayout::Yaml(layout) => {
            layout.remove(root, config.host.id())
        }
        HookLayout::Owned(_) | HookLayout::Script(_) => false,
    }
}

/// `config`'s hook file parsed, an empty object when there is none; a plugin
/// configuration as JSON5, a YAML one as YAML.
pub fn read_host(config: &HostConfig) -> Result<Value> {
    match config.layout {
        HookLayout::Plugin(_) => json5_file::read(&config.settings_path),
        HookLayout::Yaml(_) => yaml::read(&config.settings_path),
        HookLayout::Entries(_) | HookLayout::Owned(_) | HookLayout::Script(_) => {
            read_or_empty(&config.settings_path)
        }
    }
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
