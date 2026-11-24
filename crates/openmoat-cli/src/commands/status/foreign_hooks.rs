//! The `status` lines of the foreign-hook ledger (ADR-109).

use std::path::Path;

use openmoat_hosts::Host;

use super::Shown;
use crate::home::Home;
use crate::hook_ledger::{self, Review};
use crate::integrity::Lock;
use crate::report::{Mark, Row};

/// What the ledger finds for the set-up agents, for the current directory.
pub(super) fn found(home: &Home, binary: &Path) -> anyhow::Result<Review> {
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(home, binary);
    hook_ledger::review_here(home, &lock, &hosts, cwd.as_deref())
}

/// The ledger's lines in `Needs your attention`; `false` when something that
/// waits for `openmoat hooks accept` holds the agent's calls. One that does
/// not (its command is not denied, under the default `hooks.foreign: warn`)
/// is a warning that leaves the status healthy, like a hook liveness warning:
/// OpenMoat is installed as it should be, and only the person can judge it.
pub(super) fn line(shown: &mut Shown, home: &Home, binary: &Path) -> bool {
    // Without a lock there is no ledger to compare with: the lock's own line
    // already says to run `openmoat init`, as for MCP servers.
    if !home.lock_path().is_file() {
        return true;
    }
    match found(home, binary) {
        Ok(found) if !found.recorded => {
            for line in hook_ledger::lines(&found) {
                shown.needs(Mark::Attention, "Other hooks", line);
            }
            true
        }
        Ok(found) if found.changes.is_empty() => {
            let text = format!(
                "{}; nothing waits for `openmoat hooks accept`",
                hook_ledger::recorded(found.pin_count)
            );
            shown.state(Mark::Ok, "Other hooks", text);
            true
        }
        Ok(found) => {
            for change in &found.changes {
                let mark = if change.holds(found.mode) {
                    Mark::Broken
                } else {
                    Mark::Attention
                };
                let fix = format!(
                    "`openmoat hooks accept` shows it and asks; {}",
                    change.effect(found.mode)
                );
                let row = Row::new(mark, "Other hooks", change.describe()).fix(fix);
                shown.attention.push(row);
            }
            !found.holds()
        }
        Err(error) => {
            shown.needs(Mark::Broken, "Other hooks", format!("{error:#}"));
            false
        }
    }
}

/// The ledger's new and changed entries for `status --format json`.
pub(super) fn json(home: &Home, binary: &Path) -> Vec<serde_json::Value> {
    found(home, binary)
        .map(|found| {
            found
                .changes
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "host": c.found.host.map(Host::id),
                        "file": c.found.file,
                        "what": c.found.what,
                        "changed": c.changed,
                        "verdict": c.verdict.as_str(),
                        "rules": c.rules,
                        "holds": c.holds(found.mode),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
