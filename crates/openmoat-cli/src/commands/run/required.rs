//! `openmoat run` refuses to start a program it cannot bring to the
//! protection level the policy requires of it (ADR-064). The run is the OS
//! sandbox; what it cannot give is the hook: a program that is no agent
//! OpenMoat knows has none, and an agent whose hook does not run has none
//! either. A requirement it cannot check stops the run (fail closed).

use anyhow::{Result, bail};
use openmoat_core::{EvalContext, RequiredLevel};
use openmoat_hosts::Host;

use crate::home::Home;
use crate::protection::required::{self, by, level_of};
use crate::sandbox::own_login::Owner;

/// `Ok` when the program `typed` (as the person typed it), started as
/// `owner`, meets the level the policy for `ctx` requires of it under
/// `openmoat run`, or nothing is required.
pub fn check(home: &Home, ctx: &EvalContext, owner: Owner, typed: &str) -> Result<()> {
    let policy = required::policy_in(home, ctx)?;
    let host = match owner {
        Owner::Agent(host) => Some(host),
        Owner::Unknown => None,
    };
    let Some(requirement) = policy.required_for(host.map(Host::id)) else {
        return Ok(());
    };
    let level = level_of(requirement.level).label();
    let asks = by(&requirement.by);
    if requirement.level == RequiredLevel::HookAndOsSandbox
        && let Some(why) = crate::commands::run_unavailable()
    {
        bail!("{asks} requires {level}, and {why}; the program does not start");
    }
    let Some(host) = host else {
        bail!(
            "{asks} requires {level} of every agent, and `{typed}` is no agent OpenMoat knows, \
             so no hook of OpenMoat's would check its calls; it does not start"
        );
    };
    let binary = crate::install::hook_binary()?;
    let agent = crate::protection::of_host(home, &binary, host)?;
    if !agent.level.hooked() {
        let name = host.display_name();
        let why = agent.reason.as_deref().unwrap_or(agent.level.label());
        let fix = required::missing(host, agent.level, requirement.level)
            .map_or_else(String::new, |(_, fix)| format!("; to meet it, {fix}"));
        bail!(
            "{asks} requires {level} for {name}, and OpenMoat's hook does not run for it \
             ({why}), so `openmoat run` cannot meet it{fix}; {name} does not start"
        );
    }
    Ok(())
}
