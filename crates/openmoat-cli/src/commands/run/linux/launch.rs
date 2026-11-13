//! The check after the agent starts (ADR-089): the thread that starts it
//! notes the seccomp filters it already has, applies the Landlock rules and
//! seccomp filters, keeps what `restrict_self` reported, starts the agent, and
//! reads the agent's `/proc/<pid>/status`: `NoNewPrivs: 1`, `Seccomp: 2` with
//! this run's filters added to the inherited count, and an enforced ruleset.
//! Anything missing stops the agent and everything it started
//! ([`tree::stop`]) before anything else happens; the run says why and the
//! audit row records it.
//!
//! Under bubblewrap the check runs in `openmoat isolated`, inside, and is
//! reported out ([`report`]).

use std::process::{Child, Command, ExitStatus};

use anyhow::{Context as _, Result, bail};
use landlock::{RestrictionStatus, RulesetCreated, RulesetStatus};
use openmoat_core::boundary::{Enforcement, LaunchCheck, Mechanism, NetworkMode, Restriction};
use seccompiler::BpfProgram;

use crate::sandbox::landlock::abi::Kernel;

/// The launch report from inside bubblewrap, and the reply to it.
pub mod report;
/// Stopping a process and everything it started.
pub mod tree;

pub use report::{Reports, reporter};

/// How Linux holds the network where bubblewrap makes a namespace.
pub const NETWORK: NetworkMode = NetworkMode::Namespace;

/// The restrictions a Linux run plans: Landlock's steps, the seccomp filters,
/// `no_new_privs`, and bubblewrap's network namespace and view.
pub fn restrictions(isolated: bool, port_only: bool, kernel: Option<&Kernel>) -> Vec<Restriction> {
    use Mechanism as M;
    let abi = match kernel {
        Some(Kernel::Abi(abi)) => *abi,
        _ => 0,
    };
    let namespace = isolated || !port_only;
    vec![
        Restriction::planned(M::LandlockFilesystem, abi >= 4, true),
        Restriction::planned(M::LandlockTcpPort, abi >= 4, true),
        Restriction::planned(M::LandlockScopes, abi >= 6, true),
        Restriction::planned(M::LandlockResolveUnix, abi >= 9, true),
        Restriction::planned(M::Seccomp, true, true),
        Restriction::planned(M::NoNewPrivs, true, true),
        Restriction::planned(M::NetworkNamespace, namespace, namespace),
        Restriction::planned(M::IsolatedView, isolated, isolated),
    ]
}

/// Start `command` on a thread of its own restricted by `ruleset` and
/// `filters`, check the agent it started, and give the check to `on_launch`
/// (`in_bubblewrap`: this is `openmoat isolated`). A gap the check finds
/// stops the agent and its processes before `on_launch` runs; an error from
/// `on_launch` stops them too.
pub fn restricted(
    mut command: Command,
    (ruleset, filters): (RulesetCreated, Vec<BpfProgram>),
    in_bubblewrap: bool,
    on_launch: impl FnOnce(Option<LaunchCheck>) -> Result<()>,
) -> Result<ExitStatus> {
    command.env_remove(report::NONCE_ENV);
    let started = std::thread::spawn(move || -> Result<(Child, LaunchCheck)> {
        // What this thread has before it applies its own, to tell this run's
        // filters from a parent's in the agent's count.
        let inherited = std::fs::read_to_string("/proc/thread-self/status")
            .ok()
            .and_then(|text| field(&text, "Seccomp_filters:")?.parse().ok());
        let status = ruleset
            .restrict_self()
            .context("applying the Landlock rules")?;
        for filter in &filters {
            seccompiler::apply_filter(filter).context("applying the seccomp filter")?;
        }
        let child = command.spawn().context("starting the agent")?;
        let mut check = from_restriction(&status, filters.len());
        check.inherited_seccomp_filters = inherited;
        Ok((child, check))
    })
    .join()
    .ok()
    .context("the thread that starts the agent panicked")?;
    let (child, mut check) = started?;
    check.in_bubblewrap = in_bubblewrap;
    // A child that already exited is a zombie until waited for: its status
    // still shows what it ran with.
    if let Ok(text) = std::fs::read_to_string(format!("/proc/{}/status", child.id())) {
        read_status(&mut check, &text);
    }
    finish(child, check, on_launch)
}

/// Judge `check` of the started `child`: a gap stops it and its processes
/// first, then goes on record through `on_launch`, and fails the run; an
/// error from `on_launch` stops them too; otherwise wait for the agent.
fn finish(
    mut child: Child,
    mut check: LaunchCheck,
    on_launch: impl FnOnce(Option<LaunchCheck>) -> Result<()>,
) -> Result<ExitStatus> {
    check.failure = check.linux_failure();
    let failure = check.failure.clone();
    if let Some(why) = failure {
        tree::stop(&mut child);
        // On record after the agent is gone; the run stops either way.
        let _ = on_launch(Some(check));
        bail!("`openmoat run` stopped the agent right after it started: {why}");
    }
    if let Err(error) = on_launch(Some(check)) {
        tree::stop(&mut child);
        return Err(error);
    }
    child.wait().context("waiting for the agent")
}

/// What `restrict_self` reported, and how many filters applied.
fn from_restriction(status: &RestrictionStatus, filters: usize) -> LaunchCheck {
    let landlock = match status.ruleset {
        RulesetStatus::FullyEnforced => Enforcement::Full,
        RulesetStatus::PartiallyEnforced => Enforcement::Partial,
        RulesetStatus::NotEnforced => Enforcement::None,
    };
    let abi = match super::abi::from_status(status.landlock) {
        Kernel::Abi(abi) => Some(abi),
        Kernel::Missing(_) => None,
    };
    LaunchCheck {
        landlock_abi: abi,
        landlock: Some(landlock),
        no_new_privs_set: Some(status.no_new_privs),
        seccomp_filters: u32::try_from(filters).ok(),
        ..LaunchCheck::default()
    }
}

/// The value of the `/proc/<pid>/status` line `name`, if it is there.
fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

/// Fold the agent's `/proc/<pid>/status` `text` into `check`: `NoNewPrivs: 1`,
/// and `Seccomp: 2` with `Seccomp_filters` equal to the inherited count plus
/// the filters this run applied. A line that is missing leaves it unknown,
/// which the check counts as a gap.
fn read_status(check: &mut LaunchCheck, text: &str) {
    check.proc_no_new_privs = field(text, "NoNewPrivs:").map(|v| v == "1");
    check.proc_seccomp_filters = field(text, "Seccomp_filters:").and_then(|v| v.parse().ok());
    let mode = field(text, "Seccomp:").map(|v| v == "2");
    let expected = check
        .inherited_seccomp_filters
        .zip(check.seccomp_filters)
        .map(|(inherited, applied)| inherited + applied);
    check.proc_seccomp_filter = match (mode, check.proc_seccomp_filters, expected) {
        (Some(mode), Some(count), Some(expected)) => Some(mode && count == expected),
        (Some(false), _, _) => Some(false),
        _ => None,
    };
}

#[cfg(test)]
mod tests;
