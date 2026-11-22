//! `init`'s foreign-hook step (ADR-109): record the hook commands, plugin
//! hooks and git programs the set-up agents load besides OpenMoat's hook.

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;

use crate::home::Home;

/// Record what the agents load now. An unattended `init` leaves new and
/// changed entries for `openmoat hooks accept` (`hold`), as it leaves MCP
/// definitions, except on the first record, made when a lock without a
/// ledger is upgraded: that blocks nothing that was there before.
pub(super) fn record(
    home: &Home,
    binary: &Path,
    hold: bool,
    files: &mut super::Writers<'_>,
) -> Result<()> {
    let cwd = std::env::current_dir().ok();
    let recorded = crate::hook_ledger::record_current(home, binary, cwd.as_deref(), hold)?;
    writeln!(
        files.detail,
        "✔ other hooks      {} hook commands and git programs recorded; a new or changed one \
         waits for `openmoat hooks accept`",
        recorded.count
    )?;
    for change in &recorded.accepted {
        writeln!(
            files.out,
            "✔ other hooks      accepted: {}",
            change.describe().replace('\n', "\n  ")
        )?;
    }
    if !recorded.held.is_empty() {
        writeln!(
            files.out,
            "! other hooks      {} not recorded: no person at a terminal to accept them; the \
             calls of the agents that load them are held until you run `openmoat hooks \
             accept` in a terminal",
            recorded.held.len()
        )?;
        for change in &recorded.held {
            writeln!(files.out, "  {}", change.describe().replace('\n', "\n  "))?;
        }
    }
    Ok(())
}
