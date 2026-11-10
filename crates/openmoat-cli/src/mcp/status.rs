//! Each MCP server OpenMoat can read, protected or not and why, for `openmoat
//! status` and `openmoat doctor` (ADR-077). This reads definitions and the
//! lock; it never starts a server. The host starts servers itself, so
//! "protected" says what OpenMoat has in place for it, not that it was seen
//! running.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::{Host, McpCommandForm};
use serde::Serialize;
use serde_json::Value;

use super::{Review, review, servers, set_up_hosts, wrap};
use crate::home::Home;
use crate::integrity::Lock;

/// One server definition and how it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerStatus {
    /// The host that reads it, by id.
    pub host: &'static str,
    #[serde(skip)]
    pub agent: &'static str,
    pub name: String,
    pub file: PathBuf,
    pub protected: bool,
    /// Why, in words a person can act on.
    pub why: String,
    /// It runs a local command, or how it starts cannot be told.
    pub local: bool,
    /// Whether `require.run: full-boundary` counts it as a failure: a local
    /// server left unprotected, of an agent OpenMoat is set up for.
    pub fails_requirement: bool,
}

impl ServerStatus {
    /// One line for a person.
    pub fn describe(&self) -> String {
        let state = if self.protected {
            "protected"
        } else {
            "unprotected"
        };
        format!(
            "`{}` ({}, {}): {state}: {}",
            self.name,
            self.agent,
            self.file.display(),
            self.why
        )
    }
}

/// What a definition is, as far as its entry says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Wrapped {
        sandboxed: bool,
    },
    /// Runs a local command, outside `openmoat mcp proxy`; `cannot_wrap`
    /// says why `openmoat mcp wrap` cannot put it behind the proxy, when it
    /// cannot (goose's inline Python).
    Local {
        cannot_wrap: Option<&'static str>,
    },
    /// A server at an address, which runs nothing on this machine.
    Remote,
    /// Neither: OpenMoat does not know how the host starts it.
    Unknown,
}

/// The shape of `entry`, a definition its host reads in `form`.
fn shape_of(entry: &Value, form: McpCommandForm) -> Shape {
    if let Some(sandboxed) = wrap::sandboxed(entry, form) {
        return Shape::Wrapped { sandboxed };
    }
    if wrap::starts_process(entry) {
        return Shape::Local {
            cannot_wrap: wrap::not_wrappable(entry, form),
        };
    }
    let declared_remote = entry
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| !matches!(t, "stdio" | "local"));
    let has_address = ["url", "httpUrl", "serverUrl", "uri"]
        .iter()
        .any(|key| entry.get(*key).is_some());
    if declared_remote || has_address {
        Shape::Remote
    } else {
        Shape::Unknown
    }
}

/// Whether the shape is protected and why. `accepted` is whether the
/// definition is the one a person accepted; `set_up` whether OpenMoat's hook
/// is set up for the agent that reads it.
fn judged(shape: Shape, name: &str, accepted: bool, set_up: bool, agent: &str) -> (bool, String) {
    if !set_up {
        return (
            false,
            format!("OpenMoat's hook is not set up for {agent}, so nothing checks this server"),
        );
    }
    let accept = format!("`openmoat mcp accept {name}` shows it and asks");
    match (shape, accepted) {
        (Shape::Wrapped { sandboxed: true }, true) => (
            true,
            "starts through `openmoat mcp proxy` in the OS sandbox, and its definition is accepted"
                .to_owned(),
        ),
        (Shape::Wrapped { sandboxed: false }, true) => (
            true,
            "starts through `openmoat mcp proxy`, and its definition is accepted; it runs with \
             your permissions, outside the OS sandbox"
                .to_owned(),
        ),
        (Shape::Wrapped { .. }, false) => (
            false,
            format!("its definition is new or changed, so it does not start; {accept}"),
        ),
        (Shape::Local { cannot_wrap }, accepted) => (
            false,
            format!(
                "starts outside OpenMoat with your permissions; {}{}",
                cannot_wrap.map_or_else(
                    || format!("`openmoat mcp wrap {name}` checks it before it starts"),
                    wrap::cannot_wrap_advice
                ),
                if accepted {
                    String::new()
                } else {
                    format!(", and its definition is new or changed: {accept}")
                }
            ),
        ),
        (Shape::Remote, true) => (
            true,
            "runs nothing on this machine, and its definition is accepted, so its tool calls are \
             checked"
                .to_owned(),
        ),
        (Shape::Remote, false) => (
            false,
            format!("its definition is new or changed, so its tool calls are refused; {accept}"),
        ),
        (Shape::Unknown, _) => (
            false,
            "OpenMoat cannot tell how the agent starts this server, so nothing checks it"
                .to_owned(),
        ),
    }
}

/// What can be read about every server, and the files that could not be.
#[derive(Debug, Default)]
pub struct Report {
    pub servers: Vec<ServerStatus>,
    pub unreadable: Vec<(PathBuf, String)>,
}

/// Every server the agents read for a session in `cwd`.
pub fn report(home: &Home, binary: &Path, cwd: Option<&Path>) -> Result<Report> {
    let set_up: Vec<Host> = set_up_hosts(home, binary);
    let held = Lock::load(&home.lock_path())
        .and_then(|lock| review(home, &lock, &set_up, cwd))
        .unwrap_or_default();
    let mut out = Report::default();
    for host in Host::ALL.into_iter().filter(|h| h.spec().mcp.is_some()) {
        let scan = servers::scan(&servers::sources(home, host, cwd)?);
        let is_set_up = set_up.contains(&host);
        out.unreadable.extend(scan.unreadable);
        for server in scan.servers {
            let accepted = accepted(&held, &server.id);
            out.servers
                .push(status_of(host, server, accepted, is_set_up));
        }
    }
    Ok(out)
}

/// Whether the lock pins definition `id` as it stands. No pins at all, or a
/// lock that could not be read, accepts nothing.
fn accepted(review: &Review, id: &str) -> bool {
    let waiting: BTreeSet<&str> = review
        .changes
        .iter()
        .filter(|c| c.blocks())
        .map(|c| c.id.as_str())
        .collect();
    review.pinned && !waiting.contains(id)
}

fn status_of(host: Host, server: servers::Server, accepted: bool, set_up: bool) -> ServerStatus {
    let shape = shape_of(&server.entry, server.form);
    let agent = host.display_name();
    let (protected, why) = judged(shape, &server.name, accepted, set_up, agent);
    let local = matches!(
        shape,
        Shape::Wrapped { .. } | Shape::Local { .. } | Shape::Unknown
    );
    ServerStatus {
        host: host.id(),
        agent,
        name: server.name,
        file: server.file,
        protected,
        why,
        local,
        fails_requirement: local && !protected && set_up,
    }
}

/// What `require.run: full-boundary` counts as failed: each local server left
/// unprotected, and each file that hides which servers there are.
pub fn failed_requirement(home: &Home, binary: &Path, cwd: Option<&Path>) -> Vec<String> {
    match report(home, binary, cwd) {
        Ok(found) => found
            .servers
            .iter()
            .filter(|s| s.fails_requirement)
            .map(ServerStatus::describe)
            .chain(
                found
                    .unreadable
                    .iter()
                    .map(|(path, why)| format!("{} cannot be read ({why})", path.display())),
            )
            .collect(),
        Err(e) => vec![format!("the MCP servers cannot be listed: {e:#}")],
    }
}

#[cfg(test)]
mod tests;
