//! `openmoat run`'s check before it starts the agent (ADR-095): a file the
//! project holds may turn the agent's OpenMoat hook off as the session starts
//! (Claude Code's `disableAllHooks`, an OpenCode `-openmoat` entry, a goose
//! plugin named as OpenMoat's), where no call reaches the guard and no
//! settings-change hook fires. Repository content is the attacker's, so the
//! run does not start the agent over one.
//!
//! Three ways on, from the host's spec and the person's policy only:
//! OpenMoat's hook in the host's managed file, which the host's documentation
//! says a project cannot turn off (`openmoat init --managed`); the host's own
//! option that keeps hooks on for one session, added before the person's
//! arguments where every such file turns the hook off through the keys it
//! replaces; or `sandbox.project_hook_off: start` in the person's own policy,
//! which a repository policy cannot set, and which the run records.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_core::{Policy, ProjectHookOff, Verdict};
use openmoat_hosts::{Host, SessionOverride};

use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::project_settings::preflight::{self, Off};

/// The rule of the row a run started over such a file writes.
pub const STARTED_RULE: &str = "run-project-hook-off";
/// The rule of the row a run that kept the hook on with the host's option writes.
pub const OVERRIDDEN_RULE: &str = "run-project-hook-off-overridden";
/// The tool those rows name: never a host id (`isolation.rs`).
const TOOL: &str = "preflight";

/// What the check found.
#[derive(Debug, PartialEq, Eq)]
pub enum Preflight {
    /// Nothing turns the hook off, or OpenMoat's managed hook outlasts it.
    Clear,
    /// The host's option keeps the hook on: these arguments go first.
    Override {
        args: &'static [&'static str],
        files: Vec<PathBuf>,
    },
    /// The person's policy starts the agent anyway.
    Started { files: Vec<PathBuf>, what: String },
}

/// The check for `host` (the agent the run starts; `None` for a program
/// OpenMoat cannot tell) in `cwd`, with the person's arguments `rest` and
/// `policy`; an error is the refusal, with the way out.
pub fn check(
    home: &Home,
    cwd: &Path,
    host: Option<Host>,
    rest: &[OsString],
    policy: &Policy,
) -> Result<Preflight> {
    let Some(host) = host else {
        return Ok(Preflight::Clear);
    };
    let Ok(config) = HostConfig::for_host(home, host) else {
        return Ok(Preflight::Clear);
    };
    let binary = crate::install::hook_binary()?;
    // A host OpenMoat is not set up for has no hook to lose.
    if config.state(&binary) == HookState::Missing
        || crate::managed::outlasts_project(&config, &binary)
    {
        return Ok(Preflight::Clear);
    }
    let user_home = crate::home::user_home()?;
    let over = host.spec().hook_off.session_override.as_ref();
    let keys = over.map_or(&[][..], |o| o.keys);
    let off = preflight::turned_off(cwd, &user_home, host, &config.settings_path, keys);
    decide(host, &off, over, rest, policy.project_hook_off())
}

/// [`check`] once the files are read.
fn decide(
    host: Host,
    off: &[Off],
    over: Option<&SessionOverride>,
    rest: &[OsString],
    choice: ProjectHookOff,
) -> Result<Preflight> {
    if off.is_empty() {
        return Ok(Preflight::Clear);
    }
    let files: Vec<PathBuf> = off.iter().map(|o| o.path.clone()).collect();
    let clash = over.and_then(|o| clashing(o, rest));
    if let Some(over) = over.filter(|_| clash.is_none() && off.iter().all(|o| o.overridden)) {
        return Ok(Preflight::Override {
            args: over.args,
            files,
        });
    }
    let what = listed(off);
    if choice == ProjectHookOff::Start {
        return Ok(Preflight::Started { files, what });
    }
    let name = host.display_name();
    let mut ways = String::new();
    if let (Some(over), Some(clash)) = (over, &clash) {
        let _ = write!(
            ways,
            "\nOpenMoat keeps {name}'s hooks on with `{}` where that covers it, but your own \
             `{clash}` would take its place.",
            over.args.join(" ")
        );
    }
    if let Some(hooks) = crate::managed::hooks_of(host).filter(|h| h.outlasts_project)
        && let Some(path) = crate::managed::target(hooks)
    {
        let _ = write!(
            ways,
            "\nOr run `openmoat init --managed` in a terminal of your own: {name} then runs \
             OpenMoat's hook from {}, which a project's settings cannot turn off.",
            path.display()
        );
    }
    bail!(
        "`openmoat run` does not start {name}: this project turns its OpenMoat hook off when a \
         session starts, so none of the session's calls would be checked:\n{what}\nRemove that \
         setting from the project: it came with the repository, so review what else the file \
         changes.{ways}\nTo start it anyway, set `sandbox.project_hook_off: start` in your own \
         policy (`openmoat edit`); every such run is recorded."
    )
}

/// The first of the person's own arguments that would take the place of the
/// override's (`--settings`, `--settings=…`).
fn clashing(over: &SessionOverride, rest: &[OsString]) -> Option<String> {
    rest.iter().map(|a| a.to_string_lossy()).find_map(|arg| {
        over.clashes
            .iter()
            .any(|c| arg == *c || arg.starts_with(&format!("{c}=")))
            .then(|| arg.split('=').next().unwrap_or_default().to_owned())
    })
}

/// One indented line per file and what in it turns the hook off.
fn listed(off: &[Off]) -> String {
    off.iter()
        .map(|o| format!("  {}: {}", o.path.display(), o.what.join("; ")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The line the run prints before the agent starts, for what the check found.
pub fn notice(host: Option<Host>, found: &Preflight) -> Option<String> {
    let name = host.map_or("the agent", Host::display_name);
    match found {
        Preflight::Clear => None,
        Preflight::Override { args, files } => Some(format!(
            "moat run: {} would turn {name}'s hooks off; starting it with `{}`, which keeps them \
             on for this session",
            paths(files),
            args.join(" ")
        )),
        Preflight::Started { what, .. } => Some(format!(
            "moat run: warning: {name} starts without OpenMoat's hook, as your policy's \
             `sandbox.project_hook_off: start` allows; only the sandbox holds this session:\n{what}"
        )),
    }
}

fn paths(files: &[PathBuf]) -> String {
    files
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Write the run's row for what the check found, in its audit session,
/// before the agent starts. An error stops the run: the choice must be on
/// record.
pub fn record(home: &Home, (session, cwd): (&str, &str), found: &Preflight) -> Result<()> {
    let (rule, reason) = match found {
        Preflight::Clear => return Ok(()),
        Preflight::Override { args, files } => (
            OVERRIDDEN_RULE,
            format!(
                "{} turned the agent's hooks off; started with `{}`",
                paths(files),
                args.join(" ")
            ),
        ),
        Preflight::Started { what, .. } => (
            STARTED_RULE,
            format!(
                "`sandbox.project_hook_off: start` in the person's policy: the agent started \
                 without OpenMoat's hook:\n{what}"
            ),
        ),
    };
    super::isolation::write_row(home, (session, cwd), (TOOL, rule), Verdict::Allow, reason)
}

#[cfg(test)]
mod tests;
