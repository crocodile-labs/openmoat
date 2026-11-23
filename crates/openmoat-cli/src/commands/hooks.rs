//! `openmoat hooks list | accept` (ADR-109): the hook commands, plugin hooks,
//! program-running settings and git programs the agents load besides
//! OpenMoat's hook. `accept` is a person's command, like `openmoat mcp
//! accept`: it needs a terminal, no agent among its parents and an intact
//! lock, and the default policy denies it to agents.

use std::io::Write as _;

use anyhow::{Result, bail};

use crate::exit::Code;
use crate::home::Home;
use crate::hook_ledger;
use crate::integrity::{self, Lock};
use crate::render::Deferred;

/// `openmoat hooks list`: what the set-up agents load besides OpenMoat's
/// hook, recorded or not.
pub fn list() -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(&home, &binary);
    let found = hook_ledger::review_here(&home, &lock, &hosts, cwd.as_deref())?;
    let mut out = Deferred::default();
    let pins = lock.hook_ledger.clone().unwrap_or_default();
    for pin in pins.values() {
        let who = if pin.host.is_empty() {
            "git"
        } else {
            pin.host.as_str()
        };
        let line = format!("✔ {who} {} in {}\n    {}", pin.what, pin.file, pin.shown);
        writeln!(out, "{}", crate::render::clean_lines(&line))?;
    }
    for line in hook_ledger::lines(&found) {
        writeln!(out, "! {line}")?;
    }
    if pins.is_empty() && found.changes.is_empty() && found.recorded {
        writeln!(out, "no hook commands besides OpenMoat's were found")?;
    }
    out.finish()?;
    Ok(if found.changes.is_empty() && found.recorded {
        Code::Ok
    } else {
        Code::Usage
    })
}

/// `openmoat hooks accept`: show each new or changed entry and ask.
pub fn accept() -> Result<Code> {
    crate::terminal::refuse_agent("openmoat hooks accept")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat hooks accept` must be run by a person in a terminal, not from a hook or \
             script"
        );
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, "run `openmoat hooks accept`")?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    if !review_and_accept(&home, &binary, &mut out)? {
        writeln!(
            out,
            "nothing to accept: every hook command the agents load is the one accepted"
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Show every pending entry, ask, and record them on yes; `false` when
/// nothing was pending. `doctor --accept` asks through this too.
pub(in crate::commands) fn review_and_accept(
    home: &Home,
    binary: &std::path::Path,
    out: &mut Deferred,
) -> Result<bool> {
    let lock = Lock::load(&home.lock_path())?;
    let cwd = std::env::current_dir().ok();
    let hosts = crate::mcp::set_up_hosts(home, binary);
    let found = hook_ledger::review_here(home, &lock, &hosts, cwd.as_deref())?;
    if found.changes.is_empty() && found.recorded && found.gone.is_empty() {
        return Ok(false);
    }
    if !found.recorded {
        writeln!(
            out,
            "OpenMoat has not recorded the agents' other hook commands yet; accepting records \
             these:"
        )?;
    }
    for change in &found.changes {
        writeln!(out, "{}", change.describe())?;
    }
    if !found.changes.is_empty() && !super::edit::confirm(out, "Accept these hooks? [y/N] ")? {
        let after = if found.holds() {
            "the calls of the agents that load them stay held"
        } else {
            "`openmoat status` keeps naming them"
        };
        writeln!(out, "nothing was accepted; {after}")?;
        return Ok(true);
    }
    hook_ledger::accept(home, &found.changes, &found.gone)?;
    writeln!(
        out,
        "✔ accepted {} hook command(s); {} removed one(s) forgotten",
        found.changes.len(),
        found.gone.len()
    )?;
    Ok(true)
}
