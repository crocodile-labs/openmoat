//! `openmoat confine <agent>…|--all [--off]`: sandboxed start (ADR-106) after
//! `openmoat init`, for a person who said no there or set an agent up later
//! (ADR-108 §8). Typing the command is the person's yes: it writes the same
//! shims and `PATH` lines `init`'s question does, names each file, and
//! `--off` (or `openmoat uninstall`) takes them back. Refused from an agent,
//! without a terminal and over a drifted lock, as every command that re-pins
//! the lock is.

use std::io::Write as _;

use anyhow::{Result, bail};
use openmoat_hosts::Host;

use crate::cli::ConfineArgs;
use crate::exit::Code;
use crate::home::{Home, user_home};
use crate::install::HostConfig;
use crate::integrity::{self, HookPins};
use crate::protection::OsSandbox;
use crate::protection::os_sandbox::{self, RunHere};
use crate::render::Deferred;
use crate::report::Paths;
use crate::start::{self, Removed, enable};

pub fn run(args: &ConfineArgs) -> Result<Code> {
    let command = if args.off {
        "openmoat confine --off"
    } else {
        "openmoat confine"
    };
    refuse_unless_person(command)?;
    let home = Home::locate()?;
    integrity::refuse_drift(&home, "confine")?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    let changed = if args.off {
        off(&home, &chosen_off(&home, args)?, &mut out)?
    } else {
        let hosts = if args.all {
            crate::mcp::set_up_hosts(&home, &binary)
        } else {
            args.agents.clone()
        };
        on(&home, &binary, &hosts, &mut out)?
    };
    if changed {
        integrity::repin(&home, &binary, HookPins::Keep)?;
    }
    out.finish()?;
    Ok(if changed || args.all {
        Code::Ok
    } else {
        Code::Usage
    })
}

/// Only a person at a terminal, never an agent or a script.
fn refuse_unless_person(command: &str) -> Result<()> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    Ok(())
}

/// The agents `--off` takes the shims of: those named, or every one with a shim.
fn chosen_off(home: &Home, args: &ConfineArgs) -> Result<Vec<Host>> {
    if !args.all {
        return Ok(args.agents.clone());
    }
    let record = start::Record::load(home)?;
    Ok(Host::EVERY
        .into_iter()
        .filter(|h| record.of(*h).is_some())
        .collect())
}

/// Write the shims of `hosts` that can have one; why not for the others.
fn on(home: &Home, binary: &std::path::Path, hosts: &[Host], out: &mut Deferred) -> Result<bool> {
    let here = RunHere::detect();
    let search = crate::environment::absolute_search_path();
    let offers = start::offers(home, binary, hosts, &search, &here)?;
    for host in hosts
        .iter()
        .filter(|h| !offers.iter().any(|s| s.host == **h))
    {
        let why = not_offered(home, binary, *host, &here)?;
        writeln!(out, "· {:<16} {why}", host.display_name())?;
    }
    if offers.is_empty() {
        return Ok(false);
    }
    let score = crate::commands::run_default_score();
    for shim in &offers {
        writeln!(
            out,
            "  {:<16} {}: {}",
            shim.host.display_name(),
            enable::score_change(score),
            enable::what_starts(shim)
        )?;
    }
    let user = user_home()?;
    enable::enable(home, &offers, (&user, &Paths::detect()), out)?;
    Ok(true)
}

/// Why `host` gets no shim here, in a few words.
fn not_offered(
    home: &Home,
    binary: &std::path::Path,
    host: Host,
    here: &RunHere,
) -> Result<String> {
    if start::Record::load(home)?.of(host).is_some() {
        return Ok(
            "confined already: its shim is written (`openmoat status` says whether \
                   this shell finds it)"
                .to_owned(),
        );
    }
    if !HostConfig::for_host(home, host)?.set_up(binary) {
        return Ok(format!(
            "not set up: `openmoat init --hosts {}` installs its hook first",
            host.id()
        ));
    }
    if host.spec().sandbox.is_some() {
        return Ok(
            "OpenMoat writes this agent's own OS sandbox; `openmoat run` is for the agents \
             that have none"
                .to_owned(),
        );
    }
    Ok(match os_sandbox::command(home, host, here)? {
        Err(OsSandbox::Unknown { why }) => format!("no `openmoat run` command: {why}"),
        Err(OsSandbox::Unavailable { why }) => format!("cannot be confined here: {why}"),
        Err(OsSandbox::Command { command, .. }) => command,
        Ok(run) => format!(
            "`{}` is not on your PATH outside {}",
            run.program,
            start::shim_dir(home).display()
        ),
    })
}

/// Remove the shims of `hosts`; the `PATH` lines go with the last.
fn off(home: &Home, hosts: &[Host], out: &mut Deferred) -> Result<bool> {
    let before = start::Record::load(home)?;
    for host in hosts.iter().filter(|h| before.of(**h).is_none()) {
        writeln!(out, "· {:<16} not confined", host.display_name())?;
    }
    let (removed, rc) = start::remove(home, hosts)?;
    let changed = !removed.is_empty() || rc.is_some();
    for shim in removed {
        match shim {
            Removed::Deleted(path) => {
                writeln!(out, "✔ sandboxed start  {} deleted", path.display())?;
            }
            Removed::Changed(path) => writeln!(
                out,
                "! sandboxed start  {} kept: it changed since OpenMoat wrote it",
                path.display()
            )?,
        }
    }
    if let Some(rc) = rc {
        writeln!(out, "✔ sandboxed start  {rc}")?;
    }
    Ok(changed)
}
