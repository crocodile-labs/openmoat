//! `moat mcp accept | proxy | wrap | unwrap` (ADR-026).
//!
//! `accept`, `wrap` and `unwrap` are a person's commands, like `moat trust`: they
//! need a terminal and an intact lock, and the default policy denies them to
//! agents. `proxy` is what an agent host starts in place of a wrapped server.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Result, bail};
use openmoat_hosts::Host;

use crate::cli::{McpAcceptArgs, McpUnwrapArgs, McpWrapArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::Recorded;
use crate::integrity::{self, Lock};
use crate::mcp::tools::{self, ToolPins};
use crate::mcp::wrap::{self, Done};
use crate::mcp::{self, Change};
use crate::render::Deferred;

mod proxy;

pub use proxy::run as proxy;

fn person_only(command: &str) -> Result<Home> {
    crate::terminal::refuse_agent(&format!("openmoat mcp {command}"))?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat mcp {command}` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, &format!("run `openmoat mcp {command}`"))?;
    Ok(home)
}

pub fn accept(args: &McpAcceptArgs) -> Result<Code> {
    let home = person_only("accept")?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    if !review_and_accept(&home, &binary, args.server.as_deref(), &mut out)? {
        let scope = args
            .server
            .as_ref()
            .map_or_else(String::new, |s| format!(" for `{s}`"));
        writeln!(
            out,
            "nothing to accept{scope}: every MCP server and tool matches what was accepted"
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Show every pending MCP change (definitions, and tools `moat mcp proxy` holds),
/// limited to `server` when given, ask, and accept them on yes. `false` when
/// nothing was pending.
pub(super) fn review_and_accept(
    home: &Home,
    binary: &Path,
    server: Option<&str>,
    out: &mut Deferred,
) -> Result<bool> {
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let found = mcp::review(
        home,
        &lock,
        &mcp::set_up_hosts(home, binary),
        cwd.as_deref(),
    )?;
    for (path, why) in &found.unreadable {
        writeln!(
            out,
            "! cannot read {}: {why}; fix it, then run this again",
            path.display()
        )?;
    }
    let wanted = |name: &str| server.is_none_or(|s| s == name);
    let changes: Vec<Change> = found
        .changes
        .into_iter()
        .filter(|c| wanted(&c.name))
        .collect();
    let mut held: Vec<(std::path::PathBuf, ToolPins)> = tools::all(home)?
        .into_iter()
        .filter(|(_, p)| !p.held.is_empty() && wanted(&p.server))
        .collect();
    if changes.is_empty() && held.is_empty() {
        return Ok(false);
    }
    if !found.pinned {
        writeln!(
            out,
            "OpenMoat has not pinned the agents' MCP servers yet; accepting pins these:"
        )?;
    }
    for change in &changes {
        writeln!(out, "{}", change.describe())?;
    }
    for (_, pins) in &held {
        for text in pins.describe_held() {
            write!(out, "{text}")?;
        }
    }
    if !super::edit::confirm(out, "Accept these changes? [y/N] ")? {
        writeln!(
            out,
            "nothing was accepted; the changed servers' and tools' calls stay refused"
        )?;
        return Ok(true);
    }
    mcp::accept(home, &changes)?;
    let mut count = 0;
    for (path, pins) in &mut held {
        count += pins.held.len();
        pins.accept_held();
        pins.save(path)?;
    }
    writeln!(
        out,
        "✔ accepted {} server definition(s) and {count} tool(s)",
        changes.len()
    )?;
    Ok(true)
}

pub fn wrap(args: &McpWrapArgs) -> Result<Code> {
    let home = person_only("wrap")?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    let hosts = mcp::set_up_hosts(&home, &binary);
    let done = wrap_servers(
        &home,
        &binary,
        &hosts,
        &args.servers,
        args.sandbox,
        args.dry_run,
        &mut out,
    )?;
    if done == 0 {
        writeln!(out, "· no stdio MCP server to wrap")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Wrap the stdio servers named in `names` (all when empty) in the user
/// configuration of `hosts`; returns how many. `moat init --mcp-proxy` uses it.
pub(super) fn wrap_servers(
    home: &Home,
    binary: &Path,
    hosts: &[Host],
    names: &[String],
    sandbox: bool,
    dry_run: bool,
    out: &mut Deferred,
) -> Result<usize> {
    let pending = pending_ids(home, hosts)?;
    let mut edits = Vec::new();
    for (source, server) in wrap::user_servers(home, hosts)? {
        if !names.is_empty() && !names.contains(&server.name) {
            continue;
        }
        let Some(entry) = wrap::wrapped(&server.entry, binary, &server.name, sandbox) else {
            continue;
        };
        if pending.contains(&server.id) {
            skipped(out, &server.name)?;
            continue;
        }
        edits.push((source, Done { server, entry }));
    }
    let done = finish_edits(home, hosts, &edits, dry_run, true, out)?;
    first_sight_note(home, &edits, out)?;
    Ok(done)
}

/// One line on what a wrapped server with no tool pins yet does first: the
/// proxy holds every tool it lists until a person accepts them (ADR-032).
fn first_sight_note(
    home: &Home,
    edits: &[(crate::mcp::servers::Source, Done)],
    out: &mut Deferred,
) -> Result<()> {
    if home
        .load_policy()
        .is_ok_and(|policy| policy.trust_mcp_first_sight())
    {
        return Ok(());
    }
    let new: BTreeSet<&str> = edits
        .iter()
        .map(|(_, done)| done.server.name.as_str())
        .filter(|name| !tools::path(home, name).exists())
        .collect();
    if new.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = new.iter().map(|n| format!("`{n}`")).collect();
    writeln!(
        out,
        "· the tools of {} wait for `openmoat mcp accept <server>` after the server's first start",
        names.join(", ")
    )?;
    Ok(())
}

pub fn unwrap(args: &McpUnwrapArgs) -> Result<Code> {
    let home = person_only("unwrap")?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    let hosts = mcp::set_up_hosts(&home, &binary);
    if unwrap_servers(&home, &hosts, &args.servers, &mut out)? == 0 {
        writeln!(out, "· no wrapped MCP server to unwrap")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Unwrap the servers named in `names`, or every one `hosts.json` records as
/// wrapped when empty; returns how many. `moat uninstall` uses it.
pub(super) fn unwrap_servers(
    home: &Home,
    hosts: &[Host],
    names: &[String],
    out: &mut Deferred,
) -> Result<usize> {
    let recorded = Recorded::load(home)?;
    let pending = pending_ids(home, hosts)?;
    let mut edits = Vec::new();
    for (source, server) in wrap::user_servers(home, hosts)? {
        let chosen = if names.is_empty() {
            recorded
                .mcp_wrapped
                .iter()
                .any(|w| w.file == server.file && w.pointer == server.pointer)
        } else {
            names.contains(&server.name)
        };
        let Some(entry) = wrap::unwrapped(&server.entry).filter(|_| chosen) else {
            continue;
        };
        if pending.contains(&server.id) {
            skipped(out, &server.name)?;
            continue;
        }
        edits.push((source, Done { server, entry }));
    }
    finish_edits(home, hosts, &edits, false, false, out)
}

fn skipped(out: &mut Deferred, name: &str) -> Result<()> {
    writeln!(
        out,
        "! skipped `{name}`: its definition changed since it was accepted; \
         run `openmoat mcp accept {name}` first"
    )?;
    Ok(())
}

/// Ids of definitions with a change nobody accepted: rewriting one and
/// re-pinning it would accept that change unseen.
fn pending_ids(home: &Home, hosts: &[Host]) -> Result<BTreeSet<String>> {
    let path = home.lock_path();
    if !path.is_file() {
        return Ok(BTreeSet::new());
    }
    let lock = Lock::load(&path)?;
    if lock.mcp_servers.is_none() {
        return Ok(BTreeSet::new());
    }
    let found = mcp::review(home, &lock, hosts, None)?;
    Ok(found.changes.into_iter().map(|c| c.id).collect())
}

/// Write `edits`, record them and re-pin exactly what they changed: the
/// definitions, `hosts.json` (the record and the backups) and any edited file
/// the lock pins whole.
fn finish_edits(
    home: &Home,
    hosts: &[Host],
    edits: &[(crate::mcp::servers::Source, Done)],
    dry_run: bool,
    wrapping: bool,
    out: &mut Deferred,
) -> Result<usize> {
    if edits.is_empty() {
        return Ok(0);
    }
    wrap::write(home, edits, dry_run)?;
    let verb = match (dry_run, wrapping) {
        (true, _) => "would wrap",
        (false, true) => "✔ wrapped",
        (false, false) => "✔ unwrapped",
    };
    for (_, done) in edits {
        writeln!(
            out,
            "{verb} `{}` in {}",
            done.server.name,
            done.server.file.display()
        )?;
    }
    if dry_run {
        return Ok(edits.len());
    }
    let done: Vec<Done> = edits.iter().map(|(_, d)| d.clone()).collect();
    wrap::record(home, &done, wrapping)?;
    if home.lock_path().is_file() {
        // Without this, the change to the pinned `hosts.json` is drift that
        // denies every tool call (`kernel-integrity`).
        let lock = Lock::load(&home.lock_path())?;
        let mut rewritten = vec![home.hosts_path()];
        rewritten.extend(
            edits
                .iter()
                .map(|(source, _)| source.path.clone())
                .filter(|path| lock.pins(path)),
        );
        integrity::unpin(home, &[], &rewritten)?;
        let ids: BTreeSet<String> = done.iter().map(|d| d.server.id.clone()).collect();
        mcp::accept_ids(home, hosts, &ids)?;
    }
    Ok(edits.len())
}

#[cfg(test)]
mod tests;
