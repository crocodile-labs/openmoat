//! MCP servers (ADR-026).
//!
//! An agent host starts each MCP server from a definition in its configuration
//! (`servers.rs`), outside any sandbox and with the user's permissions. The
//! policy lock pins those definitions (`pins.rs`); while one differs from its pin,
//! or was added since, `moat guard` denies that server's tool calls until a person
//! accepts it (`moat mcp accept`, `moat doctor --accept`). Other servers and other
//! tools are not affected.
//!
//! `moat mcp proxy` (`relay.rs`, `tools.rs`) sits between the host and one stdio
//! server, pins each tool's name, description and input schema on first sight, and
//! hides a tool whose definition changed until a person accepts it. `wrap.rs`
//! points a server's definition at the proxy and back.

use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::Host;

use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::Lock;

pub mod pins;
pub mod relay;
pub mod servers;
pub mod tools;
pub mod wrap;

pub use pins::{Change, Pins};

/// Rule id of a tool call denied because its server's definition is not the
/// one a person accepted.
pub const SERVER_RULE: &str = "mcp-server-changed";

/// The hosts whose OpenMoat hook is installed for `binary`: the ones whose MCP
/// servers are pinned.
pub fn set_up_hosts(home: &Home, binary: &Path) -> Vec<Host> {
    Host::ALL
        .into_iter()
        .filter(|h| HostConfig::for_host(home, *h).is_ok_and(|c| c.set_up(binary)))
        .collect()
}

/// What a review of the MCP server definitions found.
#[derive(Debug, Default)]
pub struct Review {
    /// `false` when the lock predates MCP pinning: nothing is enforced yet.
    pub pinned: bool,
    /// How many definitions the lock pins.
    pub pin_count: usize,
    pub changes: Vec<Change>,
    /// Files that exist but cannot be read or parsed.
    pub unreadable: Vec<(PathBuf, String)>,
}

/// Compare the definitions `hosts` read, for a session in `cwd`, with `lock`.
pub fn review(home: &Home, lock: &Lock, hosts: &[Host], cwd: Option<&Path>) -> Result<Review> {
    let mut sources = Vec::new();
    for host in hosts {
        sources.extend(servers::sources(home, *host, cwd)?);
    }
    let scan = servers::scan(&sources);
    let empty = Pins::new();
    let pins = lock.mcp_servers.as_ref().unwrap_or(&empty);
    Ok(Review {
        pinned: lock.mcp_servers.is_some(),
        pin_count: pins.len(),
        changes: pins::changes(pins, &scan),
        unreadable: scan.unreadable,
    })
}

/// `Some(deny)` when `tool`, an MCP tool call `host` sent from `cwd`, belongs
/// to a server whose definition is not the pinned one. A configuration file
/// that cannot be read hides which server it defines, so it holds back every
/// MCP call of that host.
pub fn violation(
    home: &Home,
    host: Host,
    cwd: Option<&Path>,
    tool: &str,
) -> Result<Option<Decision>> {
    let lock = Lock::load(&home.lock_path())?;
    if lock.mcp_servers.is_none() {
        return Ok(None);
    }
    let found = review(home, &lock, &[host], cwd)?;
    let mut reasons: Vec<String> = found
        .unreadable
        .iter()
        .map(|(path, why)| {
            format!(
                "{} cannot be read ({why}), so OpenMoat cannot tell which MCP servers it starts",
                path.display()
            )
        })
        .collect();
    let mut names = Vec::new();
    for change in found
        .changes
        .iter()
        .filter(|c| c.blocks() && pins::tool_of(tool, &c.name))
    {
        reasons.push(change.describe());
        names.push(change.name.clone());
    }
    if reasons.is_empty() {
        return Ok(None);
    }
    let accept = names.first().map_or_else(
        || "fix the file, then run `moat mcp accept` in a terminal".to_owned(),
        |name| format!("a person must review it: run `moat mcp accept {name}` in a terminal"),
    );
    reasons.push(accept);
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(SERVER_RULE.to_owned());
    decision.reasons = reasons;
    Ok(Some(decision))
}

/// Store `changes` as accepted in the lock at `home`. A lock without MCP pins
/// starts them.
pub fn accept(home: &Home, changes: &[Change]) -> Result<()> {
    let path = home.lock_path();
    let mut lock = Lock::load(&path)?;
    let pins = lock.mcp_servers.get_or_insert_with(Pins::new);
    pins::apply(pins, changes);
    lock.save(&path)
}

/// Accept the current definitions with `ids`, the ones `moat mcp wrap` or
/// `unwrap` just rewrote. Nothing when the lock does not pin MCP servers yet:
/// pinning only these would hold back every other server.
pub fn accept_ids(
    home: &Home,
    hosts: &[Host],
    ids: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let lock = Lock::load(&home.lock_path())?;
    if lock.mcp_servers.is_none() {
        return Ok(());
    }
    let found = review(home, &lock, hosts, None)?;
    let chosen: Vec<Change> = found
        .changes
        .into_iter()
        .filter(|c| ids.contains(&c.id))
        .collect();
    accept(home, &chosen)
}

/// `moat init`: pin every definition the set-up hosts read now, keeping pins
/// of project files elsewhere. Returns how many definitions the lock pins.
pub fn pin_current(home: &Home, binary: &Path, cwd: Option<&Path>) -> Result<usize> {
    let lock = Lock::load(&home.lock_path())?;
    let found = review(home, &lock, &set_up_hosts(home, binary), cwd)?;
    accept(home, &found.changes)?;
    Ok(Lock::load(&home.lock_path())?
        .mcp_servers
        .map_or(0, |p| p.len()))
}

#[cfg(test)]
mod tests;
