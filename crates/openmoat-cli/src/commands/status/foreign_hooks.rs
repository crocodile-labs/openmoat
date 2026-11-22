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

/// The ledger's line; `false` when something waits for `openmoat hooks accept`.
pub(super) fn line(shown: &mut Shown, home: &Home, binary: &Path) -> bool {
    match found(home, binary) {
        Ok(found) if !found.recorded => {
            for line in hook_ledger::lines(&found) {
                shown.needs(Mark::Attention, "Other hooks", line);
            }
            true
        }
        Ok(found) if found.changes.is_empty() => {
            let text = format!(
                "{} recorded; nothing waits for `openmoat hooks accept`",
                found.pin_count
            );
            shown.state(Mark::Ok, "Other hooks", text);
            true
        }
        Ok(found) => {
            for change in &found.changes {
                let row = Row::new(Mark::Broken, "Other hooks", change.describe())
                    .fix("`openmoat hooks accept` shows it and asks; until then the agent's calls are held");
                shown.attention.push(row);
            }
            false
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
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
