//! A hook file OpenMoat owns whole ([`HookLayout::Owned`]: pi's extension, OpenCode's plugin;
//! [`HookLayout::Script`]: Cline's hook script, run for every call).
//!
//! pi has no command hook; it loads every `.js` and `.ts` file in the
//! `extensions/` of its agent directory on start (pi 1.3.0
//! `docs/configuration.md`). `moat init` writes the host's [`OwnedFile`], the
//! binary's path filled in, to its hook file (`<agent dir>/extensions/openmoat.js`).
//! The whole file is OpenMoat's: it is written whole, pinned whole by the lock
//! and deleted by `moat uninstall`. A file of the person's at that name is
//! backed up first and given back by `moat uninstall`. A host's extra files
//! ([`HostConfig::extra_files`]) get the same file: Cline runs the script as
//! its `PostToolUse` too.
//!
//! [`HookLayout::Owned`]: openmoat_hosts::HookLayout::Owned
//! [`HookLayout::Script`]: openmoat_hosts::HookLayout::Script

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::OwnedFile;

use super::{HOOK_BACKUP, HookState, HostConfig, Outcome};
use crate::home::{Home, KeepMode, write_like};

/// `file` as `init` writes it for `binary`, with `config`'s state directory.
pub fn text(config: &HostConfig, file: &OwnedFile, binary: &Path) -> Result<String> {
    let guard = config.guard(binary);
    let home = guard.home.unwrap_or_default();
    Ok(file.text(&guard.binary, &home)?)
}

/// Where `file` goes: the hook file, then the host's extra files (Cline's
/// `PostToolUse`); the other hosts' owned files have none.
fn paths(config: &HostConfig) -> Vec<PathBuf> {
    std::iter::once(config.settings_path.clone())
        .chain(config.extra_files())
        .collect()
}

/// Write `file` for `binary` at each of its [`paths`], backing up a file of
/// the person's at a name first.
pub fn install(
    home: &Home,
    config: &HostConfig,
    file: &OwnedFile,
    binary: &Path,
    dry_run: bool,
) -> Result<Outcome> {
    let wanted = text(config, file, binary)?;
    let mut outcome = Outcome::Unchanged;
    for path in paths(config) {
        let current = fs::read_to_string(&path).ok();
        let this = match &current {
            Some(text) if *text == wanted => Outcome::Unchanged,
            Some(text) if file.is_ours(text) => Outcome::Updated,
            _ => Outcome::Installed,
        };
        outcome = outcome.max(this);
        if this == Outcome::Unchanged || dry_run {
            continue;
        }
        if current.as_deref().is_some_and(|text| !file.is_ours(text)) {
            super::back_up(home, &path, HOOK_BACKUP)?;
        }
        write_like(
            &path,
            wanted.as_bytes(),
            &path,
            KeepMode::NotWritableByOthers,
        )?;
    }
    Ok(outcome)
}

/// The file of the person's at `config`'s hook file that `install` would
/// move to its backup: a whole-file hook (Cline's `PreToolUse`) replaces it,
/// so it does not run while OpenMoat is installed. `None` when there is none
/// or it is OpenMoat's.
pub fn persons_file(config: &HostConfig, file: &OwnedFile) -> Option<std::path::PathBuf> {
    let current = fs::read_to_string(&config.settings_path).ok()?;
    (!file.is_ours(&current)).then(|| super::backup_path(&config.settings_path, HOOK_BACKUP))
}

/// `file` as `init` would write it over `current`; `None` when it would not
/// change.
pub fn render(
    config: &HostConfig,
    file: &OwnedFile,
    binary: &Path,
    current: &str,
) -> Result<Option<String>> {
    let wanted = text(config, file, binary)?;
    Ok((wanted != current).then_some(wanted))
}

/// Whether `config`'s hook file is `file` as `init` writes it for `binary`. A
/// file there that `init` did not write is no hook of OpenMoat's. With the
/// hook file in place, an extra file that is not (Cline's `PostToolUse`,
/// added in a later release) leaves the hook out of date, for `init` to write.
pub fn state(config: &HostConfig, file: &OwnedFile, binary: &Path) -> HookState {
    let state = state_at(config, &config.settings_path, file, binary);
    if state != HookState::Installed {
        return state;
    }
    let extra_missing = config
        .extra_files()
        .iter()
        .any(|path| state_at(config, path, file, binary) != HookState::Installed);
    if extra_missing {
        return HookState::Stale {
            command: binary.to_string_lossy().into_owned(),
        };
    }
    state
}

/// [`state`] of the one file at `path`.
fn state_at(config: &HostConfig, path: &Path, file: &OwnedFile, binary: &Path) -> HookState {
    let current = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HookState::Missing,
        Err(e) => {
            return HookState::Unreadable(format!("reading {}: {e}", path.display()));
        }
    };
    if text(config, file, binary).is_ok_and(|wanted| wanted == current) {
        return HookState::Installed;
    }
    if !file.is_ours(&current) {
        return HookState::Missing;
    }
    HookState::Stale {
        command: file.binary(&current).unwrap_or_else(|| "?".to_owned()),
    }
}

#[cfg(test)]
mod tests;
