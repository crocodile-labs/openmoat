//! `init`'s MCP step: pin the server definitions the agents read (ADR-026) and
//! run their stdio servers through `moat mcp proxy`, by the person's choice
//! (ADR-076).

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::preview::{self, Change};
use crate::cli::InitArgs;
use crate::home::Home;
use crate::install::Recorded;
use crate::integrity;
use crate::mcp::servers::Source;
use crate::mcp::wrap::{self, Done};
use crate::render::{Deferred, clean};

/// What `init` does about wrapping the agents' stdio MCP servers.
#[derive(Debug, Clone, Copy)]
pub(super) enum Wrap {
    /// `--mcp-proxy`: wrap them, with this sandbox choice (`None`: the
    /// default, ADR-049).
    All { sandbox: Option<bool> },
    /// A person is at the terminal: show them and ask (ADR-076).
    Ask,
    /// No one to ask, or `--no-mcp-proxy`: leave them, `status` reports them.
    Leave,
}

impl Wrap {
    pub(super) fn of(args: &InitArgs, unattended: bool) -> Self {
        if args.mcp.mcp_proxy {
            return Self::All {
                sandbox: args.mcp.sandbox(),
            };
        }
        let person = !args.yes
            && !args.mcp.no_mcp_proxy
            && !unattended
            && crate::terminal::person_for("openmoat init");
        if person { Self::Ask } else { Self::Leave }
    }
}

/// Pin the MCP server definitions the agents read (ADR-026) and do what
/// `choice` says about wrapping them. Pinning first means a server that ran
/// before keeps starting once wrapped: the wrap re-pins the definition it
/// wrote (ADR-049). An unattended `init` (`unattended.rs`) leaves new and
/// changed definitions unpinned (`hold`): over an existing lock only a person
/// may add or change a pin, or a detached `openmoat init --yes`, which escapes
/// the agent check, would accept a server a cloned project planted in its
/// `.mcp.json`.
pub(super) fn servers(
    home: &Home,
    binary: &Path,
    choice: Wrap,
    hosts: &[Host],
    hold: bool,
    files: &mut super::Writers<'_>,
) -> Result<()> {
    let cwd = std::env::current_dir().ok();
    let pinned = crate::mcp::pin_current(home, binary, cwd.as_deref(), hold)?;
    writeln!(
        files.detail,
        "✔ mcp servers      {} definitions pinned; a changed or new one waits for `openmoat mcp accept`",
        pinned.count
    )?;
    let out: &mut Deferred = files.out;
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
    match choice {
        // A held definition is pending, so `wrap_plan` skips it.
        Wrap::All { sandbox } => {
            super::super::mcp::wrap_servers(home, binary, hosts, &[], sandbox, false, out)?;
        }
        Wrap::Ask => ask_and_wrap(home, binary, hosts, out)?,
        Wrap::Leave => {}
    }
    Ok(())
}

/// Show the stdio servers not yet wrapped and ask; wrap them on yes.
fn ask_and_wrap(home: &Home, binary: &Path, hosts: &[Host], out: &mut Deferred) -> Result<()> {
    let declined = Recorded::load(home)?.mcp_wrap_declined;
    let mut edits = super::super::mcp::wrap_plan(home, binary, hosts, &[], None, out)?;
    edits.retain(|(_, done)| {
        !declined.contains(&done.server.id) && wrap::sandboxed(&done.server.entry).is_none()
    });
    super::super::mcp::drop_what_cannot_be_rewritten(&mut edits, out)?;
    if edits.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\nThese MCP servers start with your permissions, unchecked, each time the agent starts \
         them:"
    )?;
    for (source, done) in &edits {
        writeln!(
            out,
            "  `{}` ({}, {})",
            clean(&done.server.name),
            source.host.display_name(),
            done.server.file.display()
        )?;
    }
    writeln!(
        out,
        "Through OpenMoat, each starts only from a definition you accepted, in `openmoat run`'s \
         sandbox where it can sandbox. Their tools stay hidden until you run `openmoat mcp accept` \
         after a server's first start, and wrapped servers do not start inside `openmoat run`. \
         `openmoat mcp unwrap` or `openmoat uninstall` undoes this."
    )?;
    let changes = changes_of(&edits);
    loop {
        write!(out, "Run them through OpenMoat? [Y/n/d] ")?;
        out.flush()?;
        // End of input is a no, asked again next time: nobody answered.
        let answer = crate::terminal::read_answer()?;
        if answer.is_empty() {
            writeln!(out)?;
            return Ok(());
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "d" | "diff" => preview::diff(&changes, out)?,
            "" | "y" | "yes" => {
                super::super::mcp::apply_wrap(home, hosts, &edits, None, false, out)?;
                return Ok(());
            }
            _ => return decline(home, &edits, out),
        }
    }
}

/// The file changes `edits` would make, for the diff.
fn changes_of(edits: &[(Source, Done)]) -> Vec<Change> {
    wrap::preview(edits)
        .into_iter()
        .filter_map(|preview| {
            let (before, after) = preview.change.ok()?;
            Some(Change::mcp_servers(preview.path, before, after))
        })
        .collect()
}

/// Remember the person's no, so `init` does not ask about these definitions
/// again; a new definition is asked about.
fn decline(home: &Home, edits: &[(Source, Done)], out: &mut Deferred) -> Result<()> {
    let mut recorded = Recorded::load(home)?;
    for (_, done) in edits {
        if !recorded.mcp_wrap_declined.contains(&done.server.id) {
            recorded.mcp_wrap_declined.push(done.server.id.clone());
        }
    }
    recorded.save(home)?;
    // `hosts.json` is pinned: without this the next tool call is drift.
    if home.lock_path().is_file() {
        integrity::unpin(home, &[], &[home.hosts_path()])?;
    }
    writeln!(
        out,
        "· left as they are; `openmoat status` keeps naming them, `openmoat mcp wrap` does this later"
    )?;
    Ok(())
}
