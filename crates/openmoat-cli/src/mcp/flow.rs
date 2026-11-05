//! MCP cross-server data flow (ADR-058): the gateway keeps what each wrapped
//! server's tool results held, and the hook holds for review a call of
//! another server's tool that writes or sends when its arguments carry it.
//!
//! Both ends read a JSON value to the same pieces ([`value_pieces`],
//! `openmoat_core::mcp_flow::pieces`) and hash them the same way
//! ([`hashed`]); the audit database keeps the hashes, by host, session and
//! server (`mcp_flow`, schema version 9), never the text.
//!
//! - `openmoat mcp proxy` ([`crate::commands::mcp`]'s gateway) records the
//!   pieces of the result of each `tools/call` it passed on, under the session
//!   of the hook's decision for that call (ADR-045).
//! - `openmoat guard` ([`checked`]) looks up the pieces of an MCP call's
//!   arguments. When another server returned one in this session, the call's
//!   tool acts ([`ToolEffect::Act`]: its pinned annotations, else its name and
//!   arguments) and neither server is in `mcp.flow_trusted`, the call needs
//!   review (`mcp-cross-server`). Calls of the server that returned the text,
//!   and tools that read, stay quiet.
//!
//! Session taint (ADR-020) and this check meet only through the audit
//! database and the order the guard applies them in: taint first, then this,
//! each only tightening. The one shared interface is
//! `Store::mcp_flow_sources` (ADR-058 §6).

use anyhow::{Context as _, Result};
use openmoat_audit::Store;
use openmoat_core::mcp_flow::{self, ToolEffect, ToolHints};
use openmoat_core::{Action, Decision, Policy, Verdict};
use openmoat_hosts::Host;
use serde_json::Value;

use crate::home::Home;
use crate::integrity::sha256_hex;
use crate::mcp::tools;

/// The most text of one value read for pieces: past this, a result is kept
/// by what came first.
const MAX_TEXT_BYTES: usize = 1 << 20;

/// Hex characters of a piece's hash kept: 128 bits, more than enough to tell
/// the pieces of one session apart.
const HASH_HEX_CHARS: usize = 32;

/// The pieces of every string in `value` (object keys left out), read as one
/// text, at most [`mcp_flow::MAX_PIECES`].
pub fn value_pieces(value: &Value) -> Vec<String> {
    let mut text = String::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        if text.len() >= MAX_TEXT_BYTES {
            break;
        }
        match value {
            Value::String(s) => {
                let room = MAX_TEXT_BYTES - text.len();
                let cut = (0..=room.min(s.len()))
                    .rev()
                    .find(|&i| s.is_char_boundary(i))
                    .unwrap_or(0);
                text.push_str(&s[..cut]);
                text.push('\n');
            }
            Value::Array(items) => pending.extend(items.iter().rev()),
            Value::Object(map) => pending.extend(map.values().rev()),
            _ => {}
        }
    }
    mcp_flow::pieces(&text)
}

/// `pieces` as the audit database keeps them: a domain-separated SHA-256 of
/// each, so the database holds no text of a result.
pub fn hashed(pieces: Vec<String>) -> Vec<String> {
    pieces
        .into_iter()
        .map(|piece| {
            let digest = sha256_hex(format!("openmoat-mcp-flow\0{piece}").as_bytes());
            digest[..HASH_HEX_CHARS].to_owned()
        })
        .collect()
}

/// What [`checked`] needs about the call being decided.
pub struct Sink<'a> {
    pub home: &'a Home,
    /// The audit log, as the hook reads it.
    pub store: &'a Store,
    pub host: Host,
    pub session: &'a str,
    pub action: &'a Action,
    /// The call's arguments in canonical form (`HookRequest::mcp_arguments`).
    pub arguments: Option<&'a str>,
    /// The effective policy, for `mcp.flow_trusted`.
    pub policy: &'a Policy,
}

/// `decision` held for review when the MCP call `sink` describes carries text
/// another MCP server returned in this session to a tool that acts; otherwise
/// as it is. Only tightens; a deny stays a deny.
pub fn checked(sink: &Sink<'_>, decision: Decision) -> Result<Decision> {
    let (Action::McpTool { name, .. }, Some(arguments)) = (sink.action, sink.arguments) else {
        return Ok(decision);
    };
    if decision.verdict == Verdict::Deny {
        return Ok(decision);
    }
    let trusted = sink.policy.mcp_flow_trusted();
    if trusted.iter().any(|t| super::tool_of(sink.host, name, t)) {
        return Ok(decision);
    }
    let arguments: Value =
        serde_json::from_str(arguments).context("reading the MCP call's arguments")?;
    let pieces = hashed(value_pieces(&arguments));
    if pieces.is_empty() {
        return Ok(decision);
    }
    let sources: Vec<String> = sink
        .store
        .mcp_flow_sources(sink.host.id(), sink.session, &pieces)
        .context("reading this session's MCP tool results from the audit log")?
        .into_iter()
        .filter(|server| !super::tool_of(sink.host, name, server) && !trusted.contains(server))
        .collect();
    if sources.is_empty() {
        return Ok(decision);
    }
    let pinned = pinned_tool(sink.home, sink.host, name)?;
    let hints = pinned.as_ref().map_or_else(ToolHints::default, |p| p.hints);
    let by_shape = openmoat_hosts::mcp_tool_acts(name, sink.action);
    if ToolEffect::classify(&hints, by_shape) == ToolEffect::Read {
        return Ok(decision);
    }
    let server = pinned.map_or_else(|| server_of(name).to_owned(), |p| p.server);
    Ok(mcp_flow::cross_server(decision, &sources, &server))
}

/// The server a wrapped tool belongs to, and the hints its accepted pin holds.
struct Pinned {
    server: String,
    hints: ToolHints,
}

/// The pin of the tool `name` (as `host` spells it) among the servers
/// `openmoat mcp proxy` pinned; a server whose pins do not hold the tool
/// gives no hints. `None` for a server never wrapped.
fn pinned_tool(home: &Home, host: Host, name: &str) -> Result<Option<Pinned>> {
    let mut server_only = None;
    for (_, pins) in tools::all(home)? {
        if !super::tool_of(host, name, &pins.server) {
            continue;
        }
        let tool = pins
            .tools
            .iter()
            .find(|(tool, _)| super::names_tool(host, name, &pins.server, tool));
        if let Some((_, pin)) = tool {
            return Ok(Some(Pinned {
                server: pins.server.clone(),
                hints: hints(&pin.annotations),
            }));
        }
        server_only.get_or_insert(Pinned {
            server: pins.server,
            hints: ToolHints::default(),
        });
    }
    Ok(server_only)
}

/// The behaviour hints of a tool's `annotations` (MCP `ToolAnnotations`).
fn hints(annotations: &Value) -> ToolHints {
    let hint = |key: &str| annotations.get(key).and_then(Value::as_bool);
    ToolHints {
        read_only: hint("readOnlyHint"),
        destructive: hint("destructiveHint"),
        open_world: hint("openWorldHint"),
    }
}

/// The server part of `mcp__<server>__<tool>`; the whole name otherwise.
fn server_of(name: &str) -> &str {
    name.strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").next())
        .filter(|server| !server.is_empty())
        .unwrap_or(name)
}

#[cfg(test)]
mod tests;
