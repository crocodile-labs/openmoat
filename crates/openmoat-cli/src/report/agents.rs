//! The `Agents` section `init`, `doctor` and `status` share: one row per
//! agent from its protection level ([`crate::protection`]), and one line for
//! the agents not on this machine.

use openmoat_hosts::Host;

use super::{Attention, Mark, Row};
use crate::protection::{Level, Protection, Required};
use crate::sandbox::install as host_sandbox;

/// The agent rows and the names of the agents not installed here.
#[derive(Debug, Default)]
pub struct AgentTable {
    pub rows: Vec<Row>,
    pub not_installed: Vec<&'static str>,
}

/// One row per agent in `agents`: `✔` with the hook, `✗` not protected, `·`
/// left out by `openmoat init`; an agent `attention` names gets `!` instead of
/// `✔`. With `verbose`, a reason that only says the agent has no OpenMoat
/// sandbox (its expected level) is shown too.
pub fn agent_table(agents: &[Protection], attention: &Attention, verbose: bool) -> AgentTable {
    let mut table = AgentTable::default();
    for agent in agents {
        let host = Host::ALL.into_iter().find(|h| h.id() == agent.host);
        let (mark, text) = match agent.level {
            Level::NotFound => {
                table.not_installed.push(agent.name);
                continue;
            }
            Level::NotSetUp => {
                let text = format!("not set up (openmoat init --hosts {})", agent.host);
                (Mark::Info, text)
            }
            Level::NotProtected => (Mark::Broken, with_reason(agent, true)),
            Level::HookOnly => {
                let expected = host.is_none_or(expected_hook_only);
                let mark = if expected { Mark::Ok } else { Mark::Attention };
                // "No OS sandbox from OpenMoat" is what hook only means; any
                // other reason (not on this system, drifted) is said.
                let no_sandbox = host.is_none_or(|h| host_sandbox::format(h).is_none());
                (mark, with_reason(agent, verbose || !no_sandbox))
            }
            Level::HookAndOsSandbox => (Mark::Ok, with_reason(agent, true)),
        };
        let mark = if mark == Mark::Ok && attention.names(agent.name) {
            Mark::Attention
        } else {
            mark
        };
        // Below the level the policy requires, every call is denied (ADR-064).
        let below = agent.required.as_ref().filter(|r| !r.met);
        let mark = if below.is_some() { Mark::Broken } else { mark };
        // The hook a version runs OpenMoat through, where versions differ
        // (OpenCode 1's and 2's).
        let through = host
            .filter(|_| agent.level.hooked())
            .and_then(crate::install::host_version::hook_api);
        let text = match through {
            Some(through) => format!("{text} · {through}"),
            None => text,
        };
        table.rows.push(Row::new(mark, agent.name, text));
        if let Some(required) = &agent.required {
            table.rows.push(required_row(agent.name, required));
        }
        if let Some(limit) = agent.limit.filter(|_| agent.level.hooked()) {
            table.rows.push(Row::new(
                Mark::Attention,
                agent.name,
                format!("limit: {limit}"),
            ));
        }
    }
    table
}

/// One row per agent at `hook only` that OpenMoat writes no sandbox for here,
/// on how to reach an OS sandbox (ADR-076): `moat status` and `moat doctor`
/// only, `moat init` having said enough.
pub fn os_sandbox_rows(agents: &[Protection]) -> Vec<Row> {
    agents
        .iter()
        .filter_map(|agent| {
            let sandbox = agent.os_sandbox.as_ref()?;
            Some(Row::new(Mark::Info, agent.name, sandbox.line()))
        })
        .collect()
}

/// One row per agent whose hook is in place but which runs a call when the
/// hook fails (ADR-079), with what to do about it: `moat status` and `moat
/// doctor`. Information, not a problem: the hook is what the agent offers.
pub fn fails_open_rows(agents: &[Protection]) -> Vec<Row> {
    agents
        .iter()
        .filter_map(|agent| {
            let line = agent.hook_failure.as_ref()?.line()?;
            Some(Row::new(Mark::Info, agent.name, line))
        })
        .collect()
}

/// The row under an agent's for the level the policy requires of it: met, or
/// what is missing and the step that brings the agent there.
fn required_row(name: &str, required: &Required) -> Row {
    let head = format!("required: {} ({})", required.label(), required.by);
    match (&required.missing, &required.fix) {
        (Some(missing), Some(fix)) => Row::new(
            Mark::Broken,
            name,
            format!("{head}, not met, so every call is denied: {missing}; to meet it, {fix}"),
        ),
        _ => Row::new(Mark::Ok, name, format!("{head}, met")),
    }
}

/// Whether hook only is all OpenMoat gives `host` here: it writes no sandbox
/// for it, or none on this system.
fn expected_hook_only(host: Host) -> bool {
    host_sandbox::format(host).is_none() || host_sandbox::unavailable(host).is_some()
}

/// The level's label, with the reason in brackets when `reason` is asked for
/// and there is one.
fn with_reason(agent: &Protection, reason: bool) -> String {
    match agent.reason.as_deref().filter(|_| reason) {
        Some(why) => format!("{} ({why})", agent.level.label()),
        None => agent.level.label().to_owned(),
    }
}
