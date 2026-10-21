//! pi: OpenMoat's extension, which is pi's hook file.
//!
//! pi has no command hook; it loads every `.js` and `.ts` file in the
//! `extensions/` of its agent directory on start (pi 1.3.0
//! `docs/configuration.md`). `moat init` writes `integrations/pi/openmoat.js`,
//! the binary's path filled in, to `<agent dir>/extensions/openmoat.js`. The
//! whole file is OpenMoat's: it is written whole, pinned whole by the lock and
//! deleted by `moat uninstall`. A file of the person's at that name is backed
//! up first and given back by `moat uninstall`.

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use super::{HOOK_BACKUP, HookState, HostConfig, Outcome};
use crate::home::{Home, write_private};

const SOURCE: &str = include_str!("../../integrations/pi/openmoat.js");
/// The line `init` fills in with the binary's path.
const BINARY_LINE: &str = "const MOAT = __MOAT_BINARY__;";
/// How every copy `init` writes begins, whichever binary it names.
const FIRST_LINE: &str = "// OpenMoat for pi.";

/// The extension as `init` writes it for `binary`.
pub fn text(binary: &Path) -> Result<String> {
    let quoted = serde_json::to_string(&binary.to_string_lossy())?;
    if SOURCE.matches(BINARY_LINE).count() != 1 {
        bail!("the pi extension source has no single `{BINARY_LINE}` line");
    }
    Ok(SOURCE.replacen(BINARY_LINE, &format!("const MOAT = {quoted};"), 1))
}

/// Whether `text` is an extension `init` wrote, for this binary or another.
pub fn is_ours(text: &str) -> bool {
    text.starts_with(FIRST_LINE)
}

/// Write the extension for `binary`, backing up a file of the person's at its
/// name first.
pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    let path = &config.settings_path;
    let wanted = text(binary)?;
    let current = fs::read_to_string(path).ok();
    let outcome = match &current {
        Some(text) if *text == wanted => Outcome::Unchanged,
        Some(text) if is_ours(text) => Outcome::Updated,
        _ => Outcome::Installed,
    };
    if outcome == Outcome::Unchanged || dry_run {
        return Ok(outcome);
    }
    if current.as_deref().is_some_and(|text| !is_ours(text)) {
        super::back_up(home, path, HOOK_BACKUP)?;
    }
    write_private(path, wanted.as_bytes())?;
    Ok(outcome)
}

/// The extension `init` would write over `current`; `None` when it would not
/// change.
pub fn render(binary: &Path, current: &str) -> Result<Option<String>> {
    let wanted = text(binary)?;
    Ok((wanted != current).then_some(wanted))
}

/// Whether the extension at `config`'s hook file is the one `init` writes for
/// `binary`. A file there that `init` did not write is no hook of OpenMoat's.
pub fn state(config: &HostConfig, binary: &Path) -> HookState {
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
    if text(binary).is_ok_and(|wanted| wanted == current) {
        return HookState::Installed;
    }
    if !is_ours(&current) {
        return HookState::Missing;
    }
    HookState::Stale {
        command: binary_of(&current).unwrap_or_else(|| "?".to_owned()),
    }
}

/// The binary an installed extension runs, for "points at another binary".
fn binary_of(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.starts_with("const MOAT = "))?;
    let literal = line.strip_prefix("const MOAT = ")?.strip_suffix(';')?;
    serde_json::from_str(literal).ok()
}

#[cfg(test)]
mod tests;
