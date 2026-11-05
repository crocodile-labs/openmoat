//! The `Agents` section `init`, `doctor` and `status` share: one row per
//! agent from its protection level ([`crate::protection`]), and one line for
//! the agents not on this machine.

use openmoat_hosts::Host;

use super::{Attention, Mark, Row};
use crate::protection::{Level, Protection};
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
        table.rows.push(Row::new(mark, agent.name, text));
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
