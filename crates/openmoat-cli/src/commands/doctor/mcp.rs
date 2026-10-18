//! The `moat doctor` lines for MCP servers (ADR-026): definitions that differ
//! from the lock's pins, and tools `moat mcp proxy` holds.

use std::path::Path;

use anyhow::Result;

use super::{Area, Report};
use crate::home::Home;
use crate::integrity::Lock;
use crate::mcp::{self, pins::Kind, tools};

pub(super) fn lines(report: &mut Report, home: &Home, lock: &Lock, binary: &Path) {
    let cwd = std::env::current_dir().ok();
    let found = match mcp::review(home, lock, &mcp::set_up_hosts(home, binary), cwd.as_deref()) {
        Ok(found) => found,
        Err(e) => {
            report.line(Area::Mcp, false, format!("mcp servers      {e:#}"));
            return;
        }
    };
    if !found.pinned {
        report.warn(
            "mcp servers      not pinned yet: `moat mcp accept` shows them and pins them, so a \
             changed definition is held back",
        );
    } else if found.changes.is_empty() && found.unreadable.is_empty() {
        report.line(
            Area::Mcp,
            true,
            format!(
                "mcp servers      {} definitions pinned, unchanged",
                found.pin_count
            ),
        );
    }
    if found.pinned {
        for change in &found.changes {
            let accept = format!("`moat mcp accept {}` shows it and asks", change.name);
            let what = match &change.kind {
                Kind::Added => "is new",
                Kind::Changed(_) => "changed; its tool calls are refused",
                Kind::Removed => "was removed",
            };
            report.line(
                Area::Mcp,
                false,
                format!(
                    "mcp servers      `{}` in {} {what}: {accept}",
                    change.name,
                    change.file.display()
                ),
            );
        }
    }
    for (path, why) in &found.unreadable {
        report.line(
            Area::Mcp,
            false,
            format!(
                "mcp servers      {} cannot be read ({why}); every MCP call of its agent is refused",
                path.display()
            ),
        );
    }
    match tools::all(home) {
        Ok(all) => {
            for (_, pins) in all.iter().filter(|(_, p)| !p.held.is_empty()) {
                report.line(
                    Area::Mcp,
                    false,
                    format!(
                        "mcp tools        `{}` lists {} tool(s) that changed or are new, hidden until \
                         `moat mcp accept {}`",
                        pins.server,
                        pins.held.len(),
                        pins.server
                    ),
                );
            }
        }
        Err(e) => report.line(Area::Mcp, false, format!("mcp tools        {e:#}")),
    }
}

/// `--accept` for MCP: show the changes and ask; on yes the MCP problems clear.
pub(super) fn accept(report: &mut Report, home: &Home, binary: &Path) -> Result<()> {
    if !super::super::mcp::review_and_accept(home, binary, None, &mut report.out)? {
        return Ok(());
    }
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let found = mcp::review(
        home,
        &lock,
        &mcp::set_up_hosts(home, binary),
        cwd.as_deref(),
    )?;
    let held = tools::all(home)?.iter().any(|(_, p)| !p.held.is_empty());
    if found.changes.is_empty() && found.unreadable.is_empty() && !held {
        report.problems.retain(|(area, _)| *area != Area::Mcp);
    }
    Ok(())
}
