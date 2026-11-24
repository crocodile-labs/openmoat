//! The `moat doctor` lines for the foreign-hook ledger (ADR-109): hook
//! commands, plugin hooks and git programs the agents load that no person
//! accepted, each with the shell classifier's verdict: a problem while it
//! holds the agent's calls, a warning otherwise.

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
                "other hooks      {}, unchanged",
                hook_ledger::recorded(found.pin_count)
            ),
        );
        return;
    }
    // One that holds the agent's calls is a problem; one that does not (by
    // default, any whose command is not denied) a warning, as in `status`.
    for change in &found.changes {
        let text = format!(
            "other hooks      {}\n  `openmoat hooks accept` shows it and asks; {}",
            change.describe().replace('\n', "\n  "),
            change.effect(found.mode)
        );
        if change.holds(found.mode) {
            report.line(Area::Hooks, false, text);
        } else {
            report.warn(&text);
        }
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
