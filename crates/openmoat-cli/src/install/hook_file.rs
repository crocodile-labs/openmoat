//! Idempotent edits to a host's JSON hook file.
//!
//! The layouts whose entries sit among the person's own (Claude Code, Codex,
//! Cursor, GitHub Copilot CLI, Gemini CLI) are pure code in the hosts crate
//! ([`openmoat_hosts::HookFile`]); this module reads, backs up and writes the
//! file. A file OpenMoat owns whole (pi's extension, OpenCode's plugin) is written by [`owned`],
//! a plugin configuration (OpenClaw's `openclaw.json`) by [`openclaw`], a YAML
//! file (Hermes Agent's `config.yaml`) by [`yaml`]; the host's spec says which
//! ([`HookLayout`]).

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::HookFileState;
use serde_json::{Map, Value};

use super::{HOOK_BACKUP, HookLayout, HostConfig, openclaw, owned, yaml};
use crate::home::{Home, write_private};

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
    /// host skips it where it cannot ask; the reason says so.
    Unapproved(String),
}

pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    // A file OpenMoat owns whole is not JSON, nor is a YAML one.
    match config.layout {
        HookLayout::Owned(file) => return owned::install(home, config, file, binary, dry_run),
        HookLayout::Yaml(layout) => return yaml::install(home, config, layout, binary, dry_run),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    let path = &config.settings_path;
    let mut root = read_host(config)?;
    let edited = upsert_all(&mut root, config, binary)?;
    let plugin = match config.layout {
        HookLayout::Plugin(plugin) => Some(plugin),
        HookLayout::Entries(_) | HookLayout::Yaml(_) | HookLayout::Owned(_) => None,
    };
    if edited != Outcome::Unchanged && plugin.is_some() {
        openclaw::read_for_edit(path)?;
    }
    // The plugin is a file of its own in the configuration directory.
    let plugin = plugin.filter(|plugin| !openclaw::plugin_current(config, plugin, binary));
    let outcome = if plugin.is_some() {
        edited.max(Outcome::Updated)
    } else {
        edited
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if let Some(plugin) = plugin {
        openclaw::write_plugin(config, plugin, binary)?;
    }
    if edited != Outcome::Unchanged {
        super::back_up(home, path, HOOK_BACKUP)?;
        let text = serde_json::to_string_pretty(&root)? + "\n";
        write_private(path, text.as_bytes())?;
    }
    Ok(outcome)
}

/// `current` (the text of the host's hook file, empty when there is none)
/// with OpenMoat's hooks in it, as [`install`] would write it; `None` when it
/// would not change. Writes nothing.
pub fn render(config: &HostConfig, binary: &Path, current: &str) -> Result<Option<String>> {
    match config.layout {
        HookLayout::Owned(file) => return owned::render(file, binary, current),
        HookLayout::Yaml(layout) => return yaml::render(config, layout, binary, current),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    if let HookLayout::Plugin(_) = config.layout {
        let parsed = openclaw::parse(current)
            .with_context(|| format!("parsing {}", config.settings_path.display()))?;
        let mut root = parsed.value.clone();
        if upsert_all(&mut root, config, binary)? == Outcome::Unchanged {
            return Ok(None);
        }
        openclaw::refuse_comments(&parsed, &config.settings_path)?;
        return Ok(Some(serde_json::to_string_pretty(&root)? + "\n"));
    }
    let mut root = crate::sandbox::install::parse_json(current)?;
    if upsert_all(&mut root, config, binary)? == Outcome::Unchanged {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&root)? + "\n"))
}

fn upsert_all(root: &mut Value, config: &HostConfig, binary: &Path) -> Result<Outcome> {
    if let HookLayout::Plugin(_) = config.layout {
        return openclaw::upsert(root, config);
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
            &binary.to_string_lossy(),
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
        HookLayout::Owned(file) => return owned::state(config, file, binary),
        HookLayout::Yaml(layout) => return yaml::state(config, layout, binary),
        HookLayout::Entries(_) | HookLayout::Plugin(_) => {}
    }
    let root = match read_host(config) {
        Ok(v) => v,
        Err(e) => return HookState::Unreadable(format!("{e:#}")),
    };
    let layout = match config.layout {
        HookLayout::Plugin(plugin) => return openclaw::state(config, plugin, binary, &root),
        HookLayout::Owned(_) | HookLayout::Yaml(_) => return HookState::Missing,
        HookLayout::Entries(layout) => layout,
    };
    let id = config.host.id();
    let binary = binary.to_string_lossy();
    match layout.state(&root, id, config.hooks, &binary, config.blocks_on_failure) {
        HookFileState::Missing => HookState::Missing,
        HookFileState::Installed => HookState::Installed,
        HookFileState::Stale { command } => HookState::Stale { command },
    }
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
        HookLayout::Plugin(_) => openclaw::remove(root),
        HookLayout::Entries(layout) | HookLayout::Yaml(layout) => {
            layout.remove(root, config.host.id())
        }
        HookLayout::Owned(_) => false,
    }
}

/// `config`'s hook file parsed, an empty object when there is none; OpenClaw's
/// as JSON5, a YAML one as YAML.
pub fn read_host(config: &HostConfig) -> Result<Value> {
    match config.layout {
        HookLayout::Plugin(_) => openclaw::read(&config.settings_path),
        HookLayout::Yaml(_) => yaml::read(&config.settings_path),
        HookLayout::Entries(_) | HookLayout::Owned(_) => read_or_empty(&config.settings_path),
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
