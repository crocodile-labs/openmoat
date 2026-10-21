//! `init`'s MCP step: pin the server definitions the agents read (ADR-026).

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::home::Home;
use crate::render::Deferred;

/// Pin the MCP server definitions the agents read (ADR-026) and, with
/// `--mcp-proxy`, run their stdio servers through `moat mcp proxy`. An
/// unattended `init` (`unattended.rs`) leaves new and changed definitions
/// unpinned (`hold`): over an existing lock only a person may add or change a
/// pin, or a detached `openmoat init --yes`, which escapes the agent check,
/// would accept a server a cloned project planted in its `.mcp.json`.
pub(super) fn servers(
    home: &Home,
    binary: &Path,
    proxy: bool,
    hosts: &[Host],
    hold: bool,
    out: &mut Deferred,
) -> Result<()> {
    let cwd = std::env::current_dir().ok();
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
