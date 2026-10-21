//! `init`'s MCP step: pin the server definitions the agents read (ADR-026).

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::home::Home;
use crate::render::Deferred;

/// Whether `init` leaves new and changed MCP definitions unpinned. A first
/// install (no lock before this run) pins what it finds, as it always has.
/// Over an existing lock only a person may add or change a pin: a detached
/// `openmoat init --yes` escapes the agent check, and would otherwise accept a
/// server a cloned project planted in its `.mcp.json`.
pub(super) fn hold_changes(lock_existed: bool, person: bool) -> bool {
    lock_existed && !person
}

/// Pin the MCP server definitions the agents read (ADR-026) and, with
/// `--mcp-proxy`, run their stdio servers through `moat mcp proxy`.
pub(super) fn servers(
    home: &Home,
    binary: &Path,
    proxy: bool,
    hosts: &[Host],
    lock_existed: bool,
    out: &mut Deferred,
) -> Result<()> {
    let cwd = std::env::current_dir().ok();
    let hold = hold_changes(lock_existed, crate::terminal::person());
    let pinned = crate::mcp::pin_current(home, binary, cwd.as_deref(), hold)?;
    writeln!(
        out,
        "✔ mcp servers      {} definitions pinned; a changed or new one waits for `openmoat mcp accept`",
        pinned.count
    )?;
    if !pinned.held.is_empty() {
        writeln!(
            out,
            "! mcp servers      {} not pinned: no person at a terminal to accept them; their tool \
             calls are denied until you run `openmoat mcp accept` in a terminal",
            pinned.held.len()
        )?;
        for change in &pinned.held {
            writeln!(out, "  {}", change.describe().replace('\n', "\n  "))?;
        }
    }
    if proxy {
        // A held definition is pending, so `wrap_servers` skips it.
        super::super::mcp::wrap_servers(home, binary, hosts, &[], false, false, out)?;
    }
    Ok(())
}
