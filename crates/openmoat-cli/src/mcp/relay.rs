//! The JSON-RPC relay inside `moat mcp proxy`, between an agent host and one
//! stdio MCP server.
//!
//! The stdio transport is one JSON-RPC message (or batch) per line. The relay
//! reads each line from the host and from the server. It changes two things only:
//!
//! - a response that lists tools (`result.tools`, whatever its id) leaves out
//!   tools held by the pins (`tools.rs`): changed since a person accepted them,
//!   or new, which every tool of a server with no pins yet is (ADR-032);
//! - a `tools/call` for a held tool, or for a tool the pins never accepted, is
//!   answered by the relay with error -32602 (unknown tool, as the MCP
//!   specification has it) naming `moat mcp accept`, and never reaches the server.
//!
//! Every `tools/call` is recorded through [`Recorder`]; one that cannot be
//! recorded is refused, as the egress proxy refuses a connection. A line from the
//! host that is not JSON the relay reads is answered with a parse error and not
//! passed on; one from the server passes through untouched: the host could not
//! read it either.

use std::io::{BufRead, Write};
use std::sync::{Mutex, PoisonError};

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use super::tools::ToolPins;

/// A line longer than this ends the session: the relay would have to hold it
/// whole to read it.
const MAX_LINE: u64 = 64 * 1024 * 1024;
/// JSON-RPC "invalid params", which MCP uses for an unknown tool.
const UNKNOWN_TOOL: i64 = -32602;
/// JSON-RPC "parse error".
const PARSE_ERROR: i64 = -32700;

/// Where the relay records each tool call.
pub trait Recorder: Send + Sync {
    /// Record a call of `tool` (`mcp__<server>__<tool>`), passed on or refused for `reason`.
    fn record(&self, tool: &str, refused: Option<&str>) -> Result<()>;
}

/// Saves the pins after a listing changed them.
pub type Save = Box<dyn Fn(&ToolPins) -> Result<()> + Send + Sync>;

pub struct Relay {
    server: String,
    state: Mutex<State>,
    recorder: Box<dyn Recorder>,
    save: Save,
    now_ms: fn() -> i64,
}

struct State {
    pins: ToolPins,
    /// No pins existed when the session started, the policy trusts first
    /// sight, and no listing came yet: the first listing is pinned as it is.
    first: bool,
    /// Why the pins could not be saved; every call is refused then.
    broken: Option<String>,
}

/// Where a line from the host goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Routed {
    /// To the server, unchanged unless part of a batch was answered.
    Server(String),
    /// Back to the host: the relay answered it.
    Host(String),
}

impl Relay {
    /// `pins` as loaded; `None` for a server never seen. A server never seen
    /// has every tool held until a person accepts it (ADR-032), unless
    /// `trust_first_sight` (the policy's `mcp.trust_first_sight`) pins its
    /// first listing as it is.
    pub fn new(
        server: &str,
        pins: Option<ToolPins>,
        trust_first_sight: bool,
        recorder: Box<dyn Recorder>,
        save: Save,
        now_ms: fn() -> i64,
    ) -> Self {
        let first = pins.is_none() && trust_first_sight;
        Self {
            server: server.to_owned(),
            state: Mutex::new(State {
                pins: pins.unwrap_or_else(|| ToolPins::new(server)),
                first,
                broken: None,
            }),
            recorder,
            save,
            now_ms,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One line from the host.
    pub fn host_line(&self, line: &str) -> Vec<Routed> {
        // A line the relay cannot read is not passed on: a server's own parser
        // may read it (a lone surrogate, an out-of-range number), and a
        // `tools/call` in it would reach the server unchecked.
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            if line.trim().is_empty() {
                return Vec::new();
            }
            let reply = json!({"jsonrpc": "2.0", "id": null, "error": {"code": PARSE_ERROR,
                "message": "OpenMoat's MCP proxy cannot read this message, so it is not passed on"}});
            return vec![Routed::Host(reply.to_string())];
        };
        let Value::Array(batch) = message else {
            return match self.request(&message) {
                Ok(()) => vec![Routed::Server(line.to_owned())],
                Err(Some(reply)) => vec![Routed::Host(reply.to_string())],
                Err(None) => Vec::new(),
            };
        };
        let (mut forward, mut replies) = (Vec::new(), Vec::new());
        for message in batch {
            match self.request(&message) {
                Ok(()) => forward.push(message),
                Err(Some(reply)) => replies.push(reply),
                Err(None) => {}
            }
        }
        let mut out = Vec::new();
        if !forward.is_empty() {
            out.push(Routed::Server(Value::Array(forward).to_string()));
        }
        if !replies.is_empty() {
            out.push(Routed::Host(Value::Array(replies).to_string()));
        }
        out
    }

    /// `Ok` to pass `message` on; `Err` with the reply to send back instead
    /// (`None` for a refused notification, which gets none).
    fn request(&self, message: &Value) -> Result<(), Option<Value>> {
        let id = message.get("id");
        match message.get("method").and_then(Value::as_str) {
            Some("tools/call") => {
                let tool = message
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let refused = self.refusal(tool);
                let name = format!("mcp__{}__{tool}", self.server);
                let refused = match self.recorder.record(&name, refused.as_deref()) {
                    Ok(()) => refused,
                    Err(e) => Some(format!(
                        "OpenMoat cannot record this call in its audit log ({e:#}), so it is refused"
                    )),
                };
                match refused {
                    None => Ok(()),
                    Some(why) => Err(id.map(|id| error(id, &why))),
                }
            }
            _ => Ok(()),
        }
    }

    /// Why a call of `tool` is refused, if it is.
    fn refusal(&self, tool: &str) -> Option<String> {
        let state = self.state();
        let server = &self.server;
        if let Some(why) = &state.broken {
            return Some(format!(
                "OpenMoat cannot save the tool definitions of MCP server `{server}` ({why}), \
                 so it refuses its tool calls"
            ));
        }
        if state.pins.is_held(tool) || (!state.first && !state.pins.tools.contains_key(tool)) {
            return Some(format!(
                "OpenMoat holds tool `{tool}` of MCP server `{server}`: its description or \
                 input schema is not the one a person accepted, or it is new. Run \
                 `openmoat mcp accept {server}` in a terminal to review it"
            ));
        }
        None
    }

    /// One line from the server, as the host gets it.
    pub fn server_line(&self, line: &str) -> String {
        let Ok(mut message) = serde_json::from_str::<Value>(line) else {
            return line.to_owned();
        };
        let changed = match &mut message {
            Value::Array(batch) => batch
                .iter_mut()
                .fold(false, |any, m| self.response(m) | any),
            single => self.response(single),
        };
        if changed {
            message.to_string()
        } else {
            line.to_owned()
        }
    }

    /// Filter a `tools/list` response; `true` when `message` changed. Every
    /// response with a tools array counts as one, whatever its id: a client
    /// matches ids by value (`Number(id)` in the TypeScript SDK), so a server
    /// answering `"2"` or `2.0` would otherwise pass a listing unfiltered.
    fn response(&self, message: &mut Value) -> bool {
        if message.get("method").is_some() {
            return false;
        }
        let mut state = self.state();
        let Some(Value::Array(tools)) = message.pointer_mut("/result/tools") else {
            return false;
        };
        let first = state.first;
        let listing = state.pins.list(tools, first, (self.now_ms)());
        state.first = false;
        if listing.changed
            && let Err(e) = (self.save)(&state.pins)
        {
            state.broken = Some(format!("{e:#}"));
        }
        let before = tools.len();
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_none_or(|n| !listing.hidden.contains(n))
        });
        tools.len() != before
    }
}

fn error(id: &Value, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": UNKNOWN_TOOL, "message": message}})
}

/// Read one line; `None` at the end of input.
fn read_line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = std::io::Read::take(&mut *input, MAX_LINE + 1)
        .read_until(b'\n', &mut bytes)
        .context("reading a message")?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() as u64 > MAX_LINE {
        bail!("a message is longer than {} MiB", MAX_LINE / (1024 * 1024));
    }
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

fn send(out: &Mutex<impl Write>, line: &str) -> Result<()> {
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Relay the host's messages from `input` until it ends: to the server, or
/// answered on `host`.
pub fn pump_host(
    relay: &Relay,
    mut input: impl BufRead,
    mut server: impl Write,
    host: &Mutex<impl Write>,
) -> Result<()> {
    while let Some(line) = read_line(&mut input)? {
        for routed in relay.host_line(&line) {
            match routed {
                Routed::Server(text) => {
                    server.write_all(text.as_bytes())?;
                    server.write_all(b"\n")?;
                    server.flush()?;
                }
                Routed::Host(text) => send(host, &text)?,
            }
        }
    }
    Ok(())
}

/// Relay the server's messages from `input` to `host` until it ends.
pub fn pump_server(relay: &Relay, mut input: impl BufRead, host: &Mutex<impl Write>) -> Result<()> {
    while let Some(line) = read_line(&mut input)? {
        send(host, &relay.server_line(&line))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
