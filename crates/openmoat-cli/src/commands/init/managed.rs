//! `openmoat init --managed` (ADR-095): OpenMoat's hook in each set-up
//! agent's managed hook file as well, which a repository's settings cannot
//! turn off. It widens what runs for every account of the machine, so like
//! the other trust-widening commands it needs a person at a terminal and no
//! agent among its parents; a file that needs root is left to a command the
//! person runs (`crate::managed`).

use std::io::Write as _;
use std::path::Path;

use anyhow::{Result, bail};
use openmoat_hosts::{Host, Managed};

use crate::home::Home;
use crate::install::HostConfig;
use crate::managed::Done;
use crate::render::Deferred;

/// The command as the checks name it.
const COMMAND: &str = "openmoat init --managed";

/// Refuse `--managed` without a person at a terminal, before anything is
/// written.
pub(super) fn refuse_unless_person() -> Result<()> {
    crate::terminal::refuse_agent(COMMAND)?;
    if !crate::terminal::interactive() {
        bail!("`{COMMAND}` must be run by a person in a terminal, not from a hook or script");
    }
    Ok(())
}

/// Write the managed hook file of each of `hosts` that has one, and name the
/// place of each that has one OpenMoat does not write.
pub(super) fn write(
    home: &Home,
    binary: &Path,
    hosts: &[Host],
    dry_run: bool,
    out: &mut Deferred,
) -> Result<()> {
    for host in hosts.iter().copied() {
        let name = host.display_name();
        let label = format!("{name:<16} managed hook");
        match &host.spec().hook_off.managed {
            Managed::Written(_) => {
                let config = HostConfig::for_host(home, host)?;
                let done = crate::managed::install(home, &config, binary, dry_run)?;
                writeln!(out, "{}", line(&label, &done, dry_run))?;
            }
            Managed::Manual { locations, why, .. } => {
                let place = locations
                    .iter()
                    .find(|f| f.platforms.contains(&crate::os_version::platform()))
                    .map(crate::managed::system_path);
                if let Some(place) = place {
                    writeln!(out, "· {label} {}: not written; {why}", place.display())?;
                }
            }
            Managed::None { .. } => {}
        }
    }
    Ok(())
}

/// The line for one host's outcome.
fn line(label: &str, done: &Done, dry_run: bool) -> String {
    match done {
        Done::Unchanged(path) => format!("✔ {label} {} (unchanged)", path.display()),
        Done::Written(path) if dry_run => format!("would write {label} {}", path.display()),
        Done::Written(path) => format!(
            "✔ {label} {}: a repository's settings cannot turn it off",
            path.display()
        ),
        Done::Staged {
            target, command, ..
        } => format!(
            "! {label} {} needs an administrator; OpenMoat does not escalate. Run:\n    {command}",
            target.display()
        ),
        Done::Skipped(why) => format!("· {label} {why}"),
    }
}
