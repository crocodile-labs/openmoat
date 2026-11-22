//! The `moat doctor` lines for the foreign-hook ledger (ADR-109): hook
//! commands, plugin hooks and git programs the agents load that no person
//! accepted, each with the shell classifier's verdict.

use std::path::Path;

use anyhow::Result;

use super::{Area, Report};
use crate::home::Home;
use crate::hook_ledger;
use crate::integrity::Lock;

pub(super) fn lines(report: &mut Report, home: &Home, lock: &Lock, binary: &Path) {
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(home, binary);
    let found = match hook_ledger::review_here(home, lock, &hosts, cwd.as_deref()) {
        Ok(found) => found,
        Err(e) => {
            report.line(Area::Hooks, false, format!("other hooks      {e:#}"));
            return;
        }
    };
    if !found.recorded {
        for line in hook_ledger::lines(&found) {
            report.warn(&line);
        }
        return;
    }
    if found.changes.is_empty() {
        report.line(
            Area::Hooks,
            true,
            format!(
                "other hooks      {} hook commands and git programs recorded, unchanged",
                found.pin_count
            ),
        );
        return;
    }
    for change in &found.changes {
        report.line(
            Area::Hooks,
            false,
            format!(
                "other hooks      {}; the agent's calls are held until `openmoat hooks accept`",
                change.describe().replace('\n', "\n  ")
            ),
        );
    }
}

/// `--accept` for the ledger: show the changes and ask; on yes its problems clear.
pub(super) fn accept(report: &mut Report, home: &Home, binary: &Path) -> Result<()> {
    if !super::super::hooks::review_and_accept(home, binary, &mut report.out)? {
        return Ok(());
    }
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(home, binary);
    let found = hook_ledger::review_here(home, &lock, &hosts, cwd.as_deref())?;
    if found.changes.is_empty() {
        report.problems.retain(|(area, _)| *area != Area::Hooks);
    }
    Ok(())
}
