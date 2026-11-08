//! Whether `moat mcp proxy` may start the server it was given (ADR-049).
//!
//! The proxy's own command line is what it would run, so that is what is
//! checked, never a file read again later: the server name, the agent it
//! serves, the sandbox flags and the command after `--` ([`Launch`]). It starts the server only when a
//! definition the agents read gives exactly that command line, and every such
//! definition is the one a person accepted: the same pin `moat guard` checks
//! a server's tool calls against (ADR-026), so `moat mcp accept` is the one
//! way to accept a server either way. A definition that sets an environment
//! variable this process does not have cannot be the one that started it, and
//! is left out; any other unaccepted definition with the same command line
//! may be, and refuses the start. A lock that cannot be read or shows drift
//! the guard would deny on, or a policy that cannot be read, trusts nothing.
//! `mcp: { trust_first_sight: true }` does not apply here: it is about a
//! server's tools (ADR-032); its definition is pinned like any other.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser as _;
use serde_json::Value;

use super::servers::{self, Scan};
use super::{Pins, pins, set_up_hosts, wrap};
use crate::cli::{Cli, Command, McpCommand, McpProxyArgs};
use crate::home::Home;
use crate::integrity;

/// The part of `moat mcp proxy`'s command line a definition fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub server: String,
    /// The agent whose hook decisions let its calls through (`--host`).
    pub host: Option<openmoat_hosts::Host>,
    pub sandbox: bool,
    pub writes: Vec<PathBuf>,
    pub command: Vec<OsString>,
}

impl Launch {
    pub fn of(args: &McpProxyArgs) -> Self {
        Self {
            server: args.server.clone(),
            host: args.host,
            sandbox: args.sandbox,
            writes: args.writes.clone(),
            command: args.command.clone(),
        }
    }

    /// The launch a wrapped definition `entry` asks for, read by the same
    /// grammar the proxy is started with; `None` when it is not wrapped.
    pub fn of_entry(entry: &Value) -> Option<Self> {
        let args = wrap::proxy_args(entry)?;
        let cli = Cli::try_parse_from(std::iter::once("openmoat".to_owned()).chain(args)).ok()?;
        match cli.command? {
            Command::Mcp {
                command: McpCommand::Proxy(proxy),
            } => Some(Self::of(&proxy)),
            _ => None,
        }
    }

    /// The server's command, for a person.
    fn shown(&self) -> String {
        self.command
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    Start,
    /// Do not start it; why, naming what a person must do.
    Refuse(String),
}

/// Whether `launch` may start, for a proxy started in `cwd` (where the
/// host's session is, whose project files are read too).
pub fn check(home: &Home, launch: &Launch, cwd: Option<&Path>) -> Startup {
    gather(home, launch, cwd).unwrap_or_else(|e| {
        Startup::Refuse(format!(
            "OpenMoat cannot check MCP server `{}` before starting it ({e:#}), so it does not \
             start it",
            launch.server
        ))
    })
}

fn gather(home: &Home, launch: &Launch, cwd: Option<&Path>) -> Result<Startup> {
    let name = &launch.server;
    let verified = match integrity::check(home) {
        Ok(verified) => verified,
        Err(e) => {
            return Ok(Startup::Refuse(format!(
                "the policy lock cannot be read ({e:#}), so OpenMoat trusts no MCP server \
                 definition and does not start `{name}`"
            )));
        }
    };
    if let Some(deny) = verified.checked.deny {
        return Ok(Startup::Refuse(format!(
            "the policy lock shows drift ({}), so OpenMoat trusts no MCP server definition and \
             does not start `{name}`; run `openmoat doctor` in a terminal",
            deny.reasons.join("; ")
        )));
    }
    if let Err(e) = verified.home.load_policy() {
        return Ok(Startup::Refuse(format!(
            "the policy cannot be read ({e:#}), so OpenMoat trusts no MCP server definition and \
             does not start `{name}`"
        )));
    }
    let Some(pins) = verified.lock.mcp_servers.as_ref() else {
        return Ok(Startup::Refuse(format!(
            "OpenMoat has not pinned the agents' MCP server definitions yet, so `{name}` is not \
             accepted; run `openmoat mcp accept {name}` in a terminal"
        )));
    };
    let binary = crate::install::hook_binary()?;
    let mut sources = Vec::new();
    for host in set_up_hosts(home, &binary) {
        sources.extend(servers::sources(home, host, cwd)?);
    }
    let scan = servers::scan(&sources);
    Ok(decide(&scan, pins, launch, |var| {
        std::env::var_os(var).is_some()
    }))
}

/// [`check`] on what was read: `scan`, the definitions the agents read, and
/// `pins`, the accepted ones; `has_env` tells whether this process has an
/// environment variable.
pub fn decide(
    scan: &Scan,
    pins: &Pins,
    launch: &Launch,
    has_env: impl Fn(&str) -> bool,
) -> Startup {
    let name = &launch.server;
    let accept = format!("a person must review it: run `openmoat mcp accept {name}` in a terminal");
    if let Some((path, why)) = scan.unreadable.first() {
        return Startup::Refuse(format!(
            "{} cannot be read ({why}), so OpenMoat cannot tell which definition starts MCP \
             server `{name}` and does not start it; fix the file, then {accept}",
            path.display()
        ));
    }
    let candidates: Vec<&servers::Server> = scan
        .servers
        .iter()
        .filter(|s| Launch::of_entry(&s.entry).as_ref() == Some(launch))
        .filter(|s| env_names(&s.entry).all(&has_env))
        .collect();
    if candidates.is_empty() {
        return Startup::Refuse(format!(
            "MCP server `{name}` is new: no definition a person accepted starts `{}`, so OpenMoat \
             does not start it; {accept}",
            launch.shown()
        ));
    }
    let changes = pins::changes(pins, scan);
    let pending: Vec<String> = candidates
        .iter()
        .filter_map(|server| {
            changes
                .iter()
                .find(|c| c.id == server.id && c.blocks())
                .map(pins::Change::describe)
        })
        .collect();
    if pending.is_empty() {
        return Startup::Start;
    }
    Startup::Refuse(format!(
        "{}; OpenMoat starts it only once a person has reviewed it: run `openmoat mcp accept \
         {name}` in a terminal",
        pending.join("; ")
    ))
}

/// The names of the environment variables `entry` sets.
fn env_names(entry: &Value) -> impl Iterator<Item = &str> {
    entry
        .get("env")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|env| env.keys().map(String::as_str))
}

#[cfg(test)]
mod tests;
