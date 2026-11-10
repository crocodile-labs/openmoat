//! The protection level a policy requires (`require:`, ADR-064): whether an
//! agent's level meets it, what is missing when it does not and the one
//! command that brings the agent there, and the guard's deny
//! (`protection-required`) for every call of an agent below it.
//!
//! The guard sees less than `openmoat status` does, and only what it can read
//! without starting a process ([`in_force`]): it runs, so the hook does; the
//! lock it verified pins the hook entries as `openmoat init` wrote them; and
//! whether an OS sandbox holds the call is the answer `session_code.rs`
//! already uses, kept under the lock's digest. What the guard cannot see is
//! the case where the hook does not run at all (turned off, a plugin not
//! loaded): then no call reaches it to deny, and only `status`, `doctor` and
//! `openmoat run` can say so (docs/LIMITS.md).

use anyhow::{Result, bail};
use openmoat_core::{Decision, Policy, Require, RequiredBy, RequiredLevel, Requirement, Verdict};
use openmoat_hosts::Host;
use serde::Serialize;

use super::{Level, os_sandboxed_by_lock};
use crate::home::Home;
use crate::integrity::Drift;
use crate::sandbox::install as host_sandbox;

pub mod boundary;

pub use boundary::Boundary;

/// The rule id of the guard's deny for an agent below the required level.
pub const RULE: &str = "protection-required";

impl Level {
    /// Whether an agent at this level meets `required`.
    pub fn meets(self, required: RequiredLevel) -> bool {
        rank(self) >= rank(level_of(required))
    }
}

/// The [`Level`] a required level names, whose label it is shown with.
pub fn level_of(required: RequiredLevel) -> Level {
    match required {
        RequiredLevel::HookOnly => Level::HookOnly,
        RequiredLevel::HookAndOsSandbox => Level::HookAndOsSandbox,
    }
}

/// How much of the policy a level enforces: the hook and a sandbox, the hook
/// alone, or nothing.
fn rank(level: Level) -> u8 {
    match level {
        Level::HookAndOsSandbox => 2,
        Level::HookOnly => 1,
        Level::NotProtected | Level::NotSetUp | Level::NotFound => 0,
    }
}

/// The required level of one agent as `status` and `doctor` show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Required {
    pub level: RequiredLevel,
    /// Which policy asks for it ([`by`]).
    pub by: String,
    /// Whether the agent's level meets it.
    pub met: bool,
    /// What the agent lacks, when it does not meet it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    /// The one step that brings the agent to the level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Required {
    /// `requirement` of `host`, at `level`.
    pub fn of(host: Host, level: Level, requirement: &Requirement) -> Self {
        let gap = missing(host, level, requirement.level);
        Self {
            level: requirement.level,
            by: by(&requirement.by),
            met: gap.is_none(),
            missing: gap.as_ref().map(|(what, _)| what.clone()),
            fix: gap.map(|(_, fix)| fix),
        }
    }

    /// The label of the level, as `status` shows levels.
    pub fn label(&self) -> &'static str {
        level_of(self.level).label()
    }
}

/// Which policy asks for a level, in the words a message uses.
pub fn by(by: &RequiredBy) -> String {
    match by {
        RequiredBy::Policy => "your policy".to_owned(),
        RequiredBy::Repository => "the repository policy".to_owned(),
        RequiredBy::Pack(name) => format!("the policy pack `{name}`"),
    }
}

/// The level of `host`'s call as the guard can see it: `hook + OS sandbox`
/// inside `openmoat run` (`within_run`, the run holds the agent) or where the
/// host's own sandbox is in place and matches the policy and the lock
/// ([`os_sandboxed_by_lock`]); otherwise `hook only`, the hook being the
/// process asking. Anything it cannot read counts as no sandbox, so a
/// requirement it cannot confirm is not met (fail closed).
pub fn in_force(home: &Home, host: Host, drifted: &[Drift], within_run: bool) -> Level {
    if within_run || os_sandboxed_by_lock(home, host, drifted) {
        Level::HookAndOsSandbox
    } else {
        Level::HookOnly
    }
}

/// What `host` at `level` lacks for `required`, and the one step that brings
/// it there; `None` when it meets it.
pub fn missing(host: Host, level: Level, required: RequiredLevel) -> Option<(String, String)> {
    if level.meets(required) {
        return None;
    }
    let name = host.display_name();
    Some(match level {
        Level::HookOnly | Level::HookAndOsSandbox => no_sandbox(host),
        Level::NotSetUp => (
            format!("OpenMoat's hook is not set up for {name}"),
            format!("run `openmoat init --hosts {}`", host.id()),
        ),
        Level::NotProtected | Level::NotFound => (
            format!("OpenMoat's hook does not run for {name}"),
            "run `openmoat doctor` in your terminal, which names what stops it".to_owned(),
        ),
    })
}

/// Why `host` has the hook but no OS sandbox from OpenMoat, and the step that
/// gives it one. Read from the host's spec and this system alone, without
/// compiling the sandbox, so the guard can say it on every call.
fn no_sandbox(host: Host) -> (String, String) {
    let name = host.display_name();
    let run = crate::commands::sandboxing_command();
    if super::writes_sandbox(host) {
        return (
            format!(
                "the OS sandbox settings OpenMoat wrote for {name} are missing or differ from \
                 the policy"
            ),
            "run `openmoat sandbox sync` in your terminal".to_owned(),
        );
    }
    let what = host_sandbox::unavailable(host).map_or_else(
        || format!("OpenMoat writes no OS sandbox for {name}"),
        str::to_owned,
    );
    match crate::commands::run_unavailable() {
        // Only that it is unavailable: the reason `openmoat run` gives when it
        // refuses tells the person how to start the agent without it.
        Some(_) => (
            format!("{what}, and `openmoat run` has no OS sandbox on this system"),
            format!("lower the level of {name} in `require.agents` with `openmoat edit`"),
        ),
        None => (what, format!("start {name} with {run}")),
    }
}

/// The deny for every call of `host` while it is below the level `policy`
/// requires of it; `None` when it meets it or nothing is required. `level`
/// is read only when something is.
pub fn unmet(policy: &Policy, host: Host, level: impl FnOnce() -> Level) -> Option<Decision> {
    let requirement = policy.required_for(Some(host.id()))?;
    let level = level();
    let (what, fix) = missing(host, level, requirement.level)?;
    let reason = format!(
        "{} requires {} for {}; this call has {}: {what}; to meet it, {fix}",
        by(&requirement.by),
        level_of(requirement.level).label(),
        host.display_name(),
        level.label(),
    );
    Some(Decision::single(Verdict::Deny, RULE, reason))
}

/// The user policy with the packs and the repository policy of `ctx`'s
/// project merged in, as far as a requirement reads it: every `require:` in
/// force there. A repository's requirement needs no trust (it only raises),
/// so its signature is not checked and no process is started; its rules are
/// merged as `openmoat run`'s proxy merges them.
pub fn policy_in(home: &Home, ctx: &openmoat_core::EvalContext) -> Result<Policy> {
    crate::repo::with_repo_denies(home, ctx, home.load_policy()?)
}

/// Refuse a `require:` that names an agent OpenMoat does not know: a typo
/// would leave that agent's level out unseen.
pub fn check_agents(require: Option<&Require>) -> Result<()> {
    for id in require.iter().flat_map(|r| r.agent_ids()) {
        if !Host::ALL.iter().any(|h| h.id() == id) {
            let known: Vec<&str> = Host::ALL.iter().map(|h| h.id()).collect();
            bail!(
                "require.agents: `{id}` is not an agent OpenMoat knows; use one of {}",
                known.join(", ")
            );
        }
    }
    Ok(())
}

/// [`check_agents`] for the policy's own `require:` and every one merged in.
pub fn check_policy(policy: &Policy) -> Result<()> {
    check_agents(policy.require.as_ref())?;
    policy
        .require_added
        .iter()
        .try_for_each(|(_, added)| check_agents(Some(added)))
}

#[cfg(test)]
mod tests;
