//! A hook file OpenMoat owns whole ([`HookLayout::Owned`]: pi's extension).
//!
//! pi has no command hook; it loads every `.js` and `.ts` file in the
//! `extensions/` of its agent directory on start (pi 1.3.0
//! `docs/configuration.md`). `moat init` writes the host's [`OwnedFile`], the
//! binary's path filled in, to its hook file (`<agent dir>/extensions/openmoat.js`).
//! The whole file is OpenMoat's: it is written whole, pinned whole by the lock
//! and deleted by `moat uninstall`. A file of the person's at that name is
//! backed up first and given back by `moat uninstall`.
//!
//! [`HookLayout::Owned`]: openmoat_hosts::HookLayout::Owned

use std::fs;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::OwnedFile;

use super::{HOOK_BACKUP, HookState, HostConfig, Outcome};
use crate::home::{Home, write_private};

/// `file` as `init` writes it for `binary`.
pub fn text(file: &OwnedFile, binary: &Path) -> Result<String> {
    Ok(file.text(&binary.to_string_lossy())?)
}

/// Write `file` for `binary`, backing up a file of the person's at its name
/// first.
pub fn install(
    home: &Home,
    config: &HostConfig,
    file: &OwnedFile,
    binary: &Path,
    dry_run: bool,
) -> Result<Outcome> {
    let path = &config.settings_path;
    let wanted = text(file, binary)?;
    let current = fs::read_to_string(path).ok();
    let outcome = match &current {
        Some(text) if *text == wanted => Outcome::Unchanged,
        Some(text) if file.is_ours(text) => Outcome::Updated,
        _ => Outcome::Installed,
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if current.as_deref().is_some_and(|text| !file.is_ours(text)) {
        super::back_up(home, path, HOOK_BACKUP)?;
    }
    write_private(path, wanted.as_bytes())?;
    Ok(outcome)
}

/// `file` as `init` would write it over `current`; `None` when it would not
/// change.
pub fn render(file: &OwnedFile, binary: &Path, current: &str) -> Result<Option<String>> {
    let wanted = text(file, binary)?;
    Ok((wanted != current).then_some(wanted))
}

/// Whether `config`'s hook file is `file` as `init` writes it for `binary`. A
/// file there that `init` did not write is no hook of OpenMoat's.
pub fn state(config: &HostConfig, file: &OwnedFile, binary: &Path) -> HookState {
    let current = match fs::read_to_string(&config.settings_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HookState::Missing,
        Err(e) => {
            return HookState::Unreadable(format!(
                "reading {}: {e}",
                config.settings_path.display()
            ));
        }
    };
    if text(file, binary).is_ok_and(|wanted| wanted == current) {
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
