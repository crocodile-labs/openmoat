//! A YAML hook file whose entries sit among the person's own
//! ([`HookLayout::Yaml`]: Hermes Agent's `config.yaml`).
//!
//! The host rewrites the file itself and people keep comments in it, so it is
//! edited as text by [`openmoat_hosts::yaml_hooks`], which changes only the
//! lines of OpenMoat's entries and checks the result parses to the document it
//! must; a file it cannot edit that way is refused with the entry to add by
//! hand. Backed up before the first edit, as every hook file is.
//!
//! [`HookLayout::Yaml`]: openmoat_hosts::HookLayout::Yaml

use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_hosts::{HookFile, HookFileState, yaml_hooks};
use serde_json::Value;

use super::{HOOK_BACKUP, HookState, HostConfig, Outcome, consent};
use crate::home::{Home, write_private};
use crate::sandbox::install::read_text;

/// Add or update OpenMoat's entries in `config`'s YAML hook file, and its
/// consent to them where the host keeps one: the consent first, so a hook
/// entry never waits on a consent that failed to write.
pub fn install(
    home: &Home,
    config: &HostConfig,
    layout: &'static dyn HookFile,
    binary: &Path,
    dry_run: bool,
) -> Result<Outcome> {
    let path = &config.settings_path;
    let current = read_text(path)?;
    let (edited, text) = edit(config, layout, binary, &current)?;
    let consent = consent::planned(config, binary)?;
    let outcome = if consent.is_some() {
        edited.max(Outcome::Updated)
    } else {
        edited
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if let Some((file, text)) = consent {
        super::back_up(home, &file, HOOK_BACKUP)?;
        write_private(&file, text.as_bytes())?;
    }
    if edited != Outcome::Unchanged {
        super::back_up(home, path, HOOK_BACKUP)?;
        write_private(path, text.as_bytes())?;
    }
    Ok(outcome)
}

/// `current` with OpenMoat's entries for `binary`, and what that changed.
fn edit(
    config: &HostConfig,
    layout: &'static dyn HookFile,
    binary: &Path,
    current: &str,
) -> Result<(Outcome, String)> {
    Ok(yaml_hooks::upsert(
        layout,
        current,
        &config.settings_path.display().to_string(),
        config.host.id(),
        config.hooks,
        &binary.to_string_lossy(),
    )?)
}

/// `current` as [`install`] would write the hook file; `None` when it would
/// not change.
pub fn render(
    config: &HostConfig,
    layout: &'static dyn HookFile,
    binary: &Path,
    current: &str,
) -> Result<Option<String>> {
    let (outcome, text) = edit(config, layout, binary, current)?;
    Ok((outcome != Outcome::Unchanged).then_some(text))
}

/// The hook file parsed, an empty mapping when there is none.
pub fn read(path: &Path) -> Result<Value> {
    yaml_hooks::parse(&read_text(path)?)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("parsing {}", path.display()))
}

/// Whether `config`'s entries run `binary` and, where the host keeps a
/// consent file, are approved there.
pub fn state(config: &HostConfig, layout: &'static dyn HookFile, binary: &Path) -> HookState {
    let root = match read(&config.settings_path) {
        Ok(root) => root,
        Err(e) => return HookState::Unreadable(format!("{e:#}")),
    };
    let id = config.host.id();
    let binary_text = binary.to_string_lossy();
    let state = match layout.state(&root, id, config.hooks, &binary_text, || false) {
        HookFileState::Missing => HookState::Missing,
        HookFileState::Stale { command } => HookState::Stale { command },
        HookFileState::Installed => match consent::missing(config, binary) {
            Some(why) => HookState::Unapproved(why),
            None => HookState::Installed,
        },
    };
    // An entry the host would run past on a failure says so, rather than
    // "out of date".
    super::hook_file::unless_fails_open(state, config, layout, &root)
}

/// The hook file's text without OpenMoat's entries; `None` when it holds
/// none.
pub fn remove(
    config: &HostConfig,
    layout: &'static dyn HookFile,
    text: &str,
) -> Result<Option<String>> {
    Ok(yaml_hooks::remove(
        layout,
        text,
        &config.settings_path.display().to_string(),
        config.host.id(),
    )?)
}

#[cfg(test)]
mod tests;
