//! `openmoat run`'s check before it starts the agent (ADR-098): a file the
//! project holds may turn the agent's OpenMoat hook off as the session starts
//! (Claude Code's `disableAllHooks`, an OpenCode `-openmoat` entry, a goose
//! plugin named as OpenMoat's), where no call reaches the guard and no
//! settings-change hook fires. Repository content is the attacker's, so the
//! run does not start the agent over one.
//!
//! The ways on, from the host's spec and the person's own settings and policy
//! only:
//! - a host with its own option that keeps hooks on for the session (Claude
//!   Code's `--settings`) gets it on every run, before the person's
//!   arguments, whatever the project holds now: the host may reload a
//!   project's files mid-session, and one managed source outranks another,
//!   so nothing checked here holds for the whole session. Not when the
//!   person passes the same option, nor when their own settings turn hooks
//!   off, which is theirs to choose and is said;
//! - for a host without one, OpenMoat's hook in the host's managed file,
//!   which the host's documentation says a project cannot turn off
//!   (`openmoat init --managed`);
//! - `sandbox.project_hook_off: start` in the person's own policy, honoured
//!   only while the policy lock holds, recorded.
//!
//! A refusal is recorded too. An agent started through a launcher OpenMoat
//! cannot tell (`npx`, `env`, a wrapper script) is not checked.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Policy, ProjectHookOff, Verdict};
use openmoat_hosts::{Host, SessionOverride};

use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::project_settings::preflight::{self, Off};

/// The rules of the rows a run started over such a file, a run that kept the
/// hook on with the host's option, a refused run, and a run whose person's own
/// settings turn hooks off write.
pub use openmoat_core::rule_id::{
    RUN_OWN_SETTINGS_HOOK_OFF as OWN_RULE, RUN_PROJECT_HOOK_OFF as STARTED_RULE,
    RUN_PROJECT_HOOK_OFF_OVERRIDDEN as OVERRIDDEN_RULE,
    RUN_PROJECT_HOOK_OFF_REFUSED as REFUSED_RULE,
};
/// The tool those rows name: never a host id (`isolation.rs`).
const TOOL: &str = "preflight";

/// What the check found.
#[derive(Debug, PartialEq, Eq)]
pub enum Preflight {
    /// Nothing turns the hook off, or OpenMoat's managed hook outlasts it.
    Clear,
    /// The host's option keeps the hook on: these arguments go first. `files`
    /// are the project files that would turn it off now; often none.
    Override {
        args: &'static [&'static str],
        files: Vec<PathBuf>,
    },
    /// The person's own settings turn the host's hooks off: no override is
    /// added, and the run says so.
    OwnOff { what: String },
    /// The person's policy starts the agent anyway.
    Started { files: Vec<PathBuf>, what: String },
    /// The run does not start: why, with the ways out.
    Refused {
        files: Vec<PathBuf>,
        message: String,
    },
}

/// The check for `host` (the agent the run starts; `None` for a program
/// OpenMoat cannot tell) in `cwd`, with the person's arguments `rest` and
/// `policy`. A refusal is written to the audit log and returned as the
/// error, with the way out.
pub fn check(
    home: &Home,
    cwd: &Path,
    host: Option<Host>,
    rest: &[OsString],
    policy: &Policy,
) -> Result<Preflight> {
    let found = find(home, cwd, host, rest, policy)?;
    if let Preflight::Refused { message, .. } = &found {
        let session = format!("run-{}-preflight", crate::time::now_ms());
        if let Err(error) = record(home, (&session, &cwd.to_string_lossy()), &found) {
            bail!("{message}\n(the refusal could not be recorded: {error:#})");
        }
        bail!("{message}");
    }
    Ok(found)
}

/// [`check`] before the refusal is recorded.
fn find(
    home: &Home,
    cwd: &Path,
    host: Option<Host>,
    rest: &[OsString],
    policy: &Policy,
) -> Result<Preflight> {
    let Some(host) = host else {
        return Ok(Preflight::Clear);
    };
    // Where the agent's hook file is not known, neither is whether a
    // project turns it off: refused, not cleared.
    let config = HostConfig::for_host(home, host).with_context(|| {
        format!(
            "`openmoat run` does not start {}: where its OpenMoat hook is cannot be told",
            host.display_name()
        )
    })?;
    let binary = crate::install::hook_binary()?;
    // A host OpenMoat is not set up for has no hook to lose.
    if config.state(&binary) == HookState::Missing {
        return Ok(Preflight::Clear);
    }
    let over = host.spec().hook_off.session_override.as_ref();
    // A file of the person's that cannot be read says nothing they chose.
    if over.is_some()
        && let Some(what) =
            crate::project_settings::switched_off(host, config.dir(), &config.settings_path)
                .filter(|what| !what.contains("cannot be checked"))
    {
        return Ok(Preflight::OwnOff { what });
    }
    if over.is_none() && crate::managed::outlasts_project(&config, &binary) {
        return Ok(Preflight::Clear);
    }
    let user_home = crate::home::user_home()?;
    let keys = over.map_or(&[][..], |o| o.keys);
    let off = preflight::turned_off(cwd, &user_home, host, &config.settings_path, keys);
    let mut choice = policy.project_hook_off();
    // `start` counts only from the policy the lock pins.
    if choice == ProjectHookOff::Start && !off.is_empty() && lock_drifted(home)? {
        choice = ProjectHookOff::Refuse;
    }
    Ok(decide(host, &off, over, rest, choice))
}

/// Whether the policy lock no longer matches what it pins.
fn lock_drifted(home: &Home) -> Result<bool> {
    Ok(crate::integrity::violation(home)?.is_some())
}

/// [`find`] once the files are read.
fn decide(
    host: Host,
    off: &[Off],
    over: Option<&SessionOverride>,
    rest: &[OsString],
    choice: ProjectHookOff,
) -> Preflight {
    let files: Vec<PathBuf> = off.iter().map(|o| o.path.clone()).collect();
    let clash = over.and_then(|o| clashing(o, rest));
    if let Some(over) = over.filter(|_| clash.is_none() && off.iter().all(|o| o.overridden)) {
        return Preflight::Override {
            args: over.args,
            files,
        };
    }
    if off.is_empty() {
        return Preflight::Clear;
    }
    let what = listed(off);
    if choice == ProjectHookOff::Start {
        return Preflight::Started { files, what };
    }
    let name = host.display_name();
    let mut ways = String::new();
    if let (Some(over), Some(clash)) = (over, &clash) {
        let _ = write!(
            ways,
            "\nOpenMoat keeps {name}'s hooks on with `{}`, but your own `{clash}` would take \
             its place.",
            over.args.join(" ")
        );
    }
    if over.is_none()
        && let Some(hooks) = crate::managed::hooks_of(host).filter(|h| h.outlasts_project)
        && let Some(path) = crate::managed::target(hooks)
    {
        let _ = write!(
            ways,
            "\nOr run `openmoat init --managed` in a terminal of your own: {name} then runs \
             OpenMoat's hook from {}, which a project's settings cannot turn off.",
            path.display()
        );
    }
    Preflight::Refused {
        files,
        message: format!(
            "`openmoat run` does not start {name}: this project turns its OpenMoat hook off when \
             a session starts, so none of the session's calls would be checked:\n{what}\nRemove \
             that setting from the project: it came with the repository, so review what else \
             the file changes.{ways}\nTo start it anyway, set `sandbox.project_hook_off: start` \
             in your own policy (`openmoat edit`); every such run is recorded."
        ),
    }
}

/// The first of the person's own options, before a `--` that ends them, that
/// would take the place of the override's (`--settings`, `--settings=…`). A
/// prompt that mentions the option is a word of its own, never equal to it.
fn clashing(over: &SessionOverride, rest: &[OsString]) -> Option<String> {
    rest.iter()
        .map(|a| a.to_string_lossy())
        .take_while(|arg| arg != "--")
        .filter(|arg| arg.starts_with('-'))
        .find_map(|arg| {
            over.clashes
                .iter()
                .find(|c| arg == **c || arg.starts_with(&format!("{c}=")))
                .map(|c| (*c).to_owned())
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
        Preflight::Clear | Preflight::Refused { .. } => None,
        Preflight::Override { args, files } if files.is_empty() => Some(format!(
            "moat run: starting {name} with `{}`, which keeps its hooks on whatever the \
             project's settings say",
            args.join(" ")
        )),
        Preflight::Override { args, files } => Some(format!(
            "moat run: {} would turn {name}'s hooks off; starting it with `{}`, which keeps them \
             on for this session",
            paths(files),
            args.join(" ")
        )),
        Preflight::OwnOff { what } => Some(format!(
            "moat run: your own settings turn {name}'s hooks off ({what}); OpenMoat leaves that \
             as it is, so its hook checks none of this session's calls and only the sandbox holds"
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
    let (rule, verdict, reason) = match found {
        Preflight::Clear => return Ok(()),
        // The option on every run is the default; a row only when a file
        // would have turned the hooks off.
        Preflight::Override { files, .. } if files.is_empty() => return Ok(()),
        Preflight::Override { args, files } => (
            OVERRIDDEN_RULE,
            Verdict::Allow,
            format!(
                "{} turned the agent's hooks off; started with `{}`",
                paths(files),
                args.join(" ")
            ),
        ),
        Preflight::OwnOff { what } => (
            OWN_RULE,
            Verdict::Allow,
            format!("the person's own settings turn the agent's hooks off: {what}"),
        ),
        Preflight::Started { what, .. } => (
            STARTED_RULE,
            Verdict::Allow,
            format!(
                "`sandbox.project_hook_off: start` in the person's policy: the agent started \
                 without OpenMoat's hook:\n{what}"
            ),
        ),
        Preflight::Refused { files, .. } => (
            REFUSED_RULE,
            Verdict::Deny,
            format!(
                "{} turned the agent's hooks off; the run did not start",
                paths(files)
            ),
        ),
    };
    super::isolation::write_row(home, (session, cwd), (TOOL, rule), verdict, reason)
}

#[cfg(test)]
mod tests;
