//! Idempotent edits to a host's JSON hook file.
//!
//! The layouts whose entries sit among the person's own (Claude Code, Codex,
//! Cursor, GitHub Copilot CLI, Gemini CLI) are pure code in the hosts crate
//! ([`openmoat_hosts::HookFile`]); this module reads, backs up and writes the
//! file. OpenClaw's `openclaw.json` and pi's extension are edited by
//! [`openclaw`] and [`pi`].

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{HookFile, HookFileState};
use serde_json::{Map, Value};

use super::{HOOK_BACKUP, HookFormat, HostConfig, openclaw, pi};
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
}

pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    // pi's hook file is OpenMoat's extension itself, not JSON.
    if config.format == HookFormat::Pi {
        return pi::install(home, config, binary, dry_run);
    }
    let path = &config.settings_path;
    let mut root = read_host(config)?;
    let edited = upsert_all(&mut root, config, binary)?;
    if edited != Outcome::Unchanged && config.format == HookFormat::OpenClaw {
        openclaw::read_for_edit(path)?;
    }
    // OpenClaw's hook is a plugin file in its state directory.
    let plugin = config.format == HookFormat::OpenClaw && !openclaw::plugin_current(config, binary);
    let outcome = if plugin {
        edited.max(Outcome::Updated)
    } else {
        edited
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if plugin {
        openclaw::write_plugin(config, binary)?;
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
    if config.format == HookFormat::Pi {
        return pi::render(binary, current);
    }
    if config.format == HookFormat::OpenClaw {
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
    if config.format == HookFormat::OpenClaw {
        return openclaw::upsert(root, config);
    }
    let Some(layout) = layout(config) else {
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

/// The code for `config`'s layout; `None` for the files OpenMoat owns whole.
fn layout(config: &HostConfig) -> Option<&'static dyn HookFile> {
    config.format.hook_file()
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
    if config.format == HookFormat::Pi {
        return pi::state(config, binary);
    }
    let root = match read_host(config) {
        Ok(v) => v,
        Err(e) => return HookState::Unreadable(format!("{e:#}")),
    };
    if config.format == HookFormat::OpenClaw {
        return openclaw::state(config, binary, &root);
    }
    let Some(layout) = layout(config) else {
        return HookState::Missing;
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
    layout(config).is_some_and(|l| l.lacks_on_failure(&root, config.host.id(), config.hooks))
}

/// The inverse of [`install`] on a parsed file: remove every entry of ours, then
/// the events and `hooks` object that leaves empty, and Cursor's `version` when
/// nothing else remains. Returns whether anything was removed.
pub fn remove(root: &mut Value, config: &HostConfig) -> bool {
    if config.format == HookFormat::OpenClaw {
        return openclaw::remove(root);
    }
    layout(config).is_some_and(|l| l.remove(root, config.host.id()))
}

/// `config`'s hook file parsed, an empty object when there is none; OpenClaw's
/// as JSON5.
pub fn read_host(config: &HostConfig) -> Result<Value> {
    if config.format == HookFormat::OpenClaw {
        return openclaw::read(&config.settings_path);
    }
    read_or_empty(&config.settings_path)
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
