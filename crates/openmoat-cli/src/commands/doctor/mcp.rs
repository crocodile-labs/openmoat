//! The `moat doctor` lines for MCP servers (ADR-026): definitions that differ
//! from the lock's pins, and tools `moat mcp proxy` holds.

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;

use super::{Area, Place, Report};
use crate::home::Home;
use crate::integrity::Lock;
use crate::mcp::{self, pins::Kind, tools};

/// The start of the line naming values an older version kept in clear.
const CLEAR_VALUES: &str = "mcp servers      the lock keeps";

pub(super) fn lines(report: &mut Report, home: &Home, lock: &Lock, binary: &Path) {
    let clear = lock.mcp_servers.as_ref().map_or(0, mcp::pins::clear_values);
    if clear > 0 {
        report.line(
            Area::Mcp,
            false,
            format!(
                "{CLEAR_VALUES} {clear} MCP server variable or header value(s) in clear, written \
                 by an older OpenMoat: `openmoat doctor --accept` rewrites it without them; every \
                 definition stays pinned as it is, so nothing needs accepting again"
            ),
        );
    }
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
            "mcp servers      not pinned yet: `openmoat mcp accept` shows them and pins them, so a \
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
            let accept = format!(
                "`openmoat mcp accept {}` shows it and asks",
                crate::render::clean(&change.name)
            );
            let what = match &change.kind {
                Kind::Added => "is new",
                Kind::Changed(_) => "changed; its tool calls are refused",
                Kind::Removed => "was removed",
            };
            report.line(
                Area::Mcp,
                false,
                format!(
                    "mcp servers      {} in {} {what}: {accept}",
                    crate::render::Named(&change.name),
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
    // Warnings: the person decides whether to wrap them (ADR-049).
    match mcp::outside::report(home, binary, cwd.as_deref()) {
        Ok(found) => {
            for outside in &found {
                report.warn(&format!("mcp servers      {}", outside.describe()));
            }
        }
        Err(e) => report.warn(&format!(
            "mcp servers      cannot list the servers that start outside OpenMoat: {e:#}"
        )),
    }
    match tools::all(home) {
        Ok(all) => {
            for (_, pins) in all.iter().filter(|(_, p)| p.held_count() > 0) {
                report.line(
                    Area::Mcp,
                    false,
                    format!(
                        "mcp tools        `{}` lists {}, hidden until `openmoat mcp accept {}`",
                        pins.server,
                        pins.held_summary(),
                        pins.server
                    ),
                );
            }
        }
        Err(e) => report.line(Area::Mcp, false, format!("mcp tools        {e:#}")),
    }
}

/// Each MCP server OpenMoat can read, protected or not and why (ADR-077).
pub(super) fn servers(report: &mut Report, home: &Home, binary: &Path) {
    let cwd = std::env::current_dir().ok();
    match mcp::status::report(home, binary, cwd.as_deref()) {
        Ok(found) => {
            for server in &found.servers {
                let line = format!("mcp server       {}", server.describe());
                if server.protected {
                    report.note_at(&line, Place::OpenMoat);
                } else {
                    report.warn(&line);
                }
            }
        }
        Err(e) => report.warn(&format!("mcp servers      cannot list them: {e:#}")),
    }
}

/// `--accept` for MCP: show the changes and ask; on yes the MCP problems clear.
pub(super) fn accept(report: &mut Report, home: &Home, binary: &Path) -> Result<()> {
    let scrubbed = mcp::scrub_lock(home)?;
    if scrubbed > 0 {
        writeln!(
            report.out,
            "✔ mcp servers      {scrubbed} value(s) an older OpenMoat kept in clear removed from \
             the lock; every definition stays pinned as it was"
        )?;
    }
    // Decided from the lock as it is now: a re-pin before this saved it
    // without the values already, so nothing was left here to remove.
    let still = Lock::load(&home.lock_path())?
        .mcp_servers
        .as_ref()
        .map_or(0, mcp::pins::clear_values);
    if still == 0 {
        report
            .problems
            .retain(|(area, line)| !(*area == Area::Mcp && line.starts_with(CLEAR_VALUES)));
    }
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
    let held = tools::all(home)?.iter().any(|(_, p)| p.held_count() > 0);
    if found.changes.is_empty() && found.unreadable.is_empty() && !held {
        report.problems.retain(|(area, _)| *area != Area::Mcp);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
