//! The JSON-RPC relay inside `moat mcp proxy`, between an agent host and one
//! stdio MCP server: the MCP gateway (ADR-045).
//!
//! The stdio transport is one JSON-RPC message (or batch) per line. The relay
//! reads each line whole, checks it, and passes on only what it read, written
//! again as compact JSON: a server or host never receives bytes the relay did
//! not check, so no difference between its JSON reader and theirs (a `\r`
//! inside a line, a key given twice, a number written two ways) can carry a
//! message past it. What it cannot read is not passed on: the host gets a parse
//! error for its own line, a server's line is dropped.
//!
//! From the host ([`host`]):
//! - a `tools/call` of a tool the pins hold or never accepted is answered with
//!   error -32602 naming `moat mcp accept` (ADR-026, ADR-032), and so is every
//!   call while the server's tools are being read again after it said they
//!   changed;
//! - every `tools/call` the pins let through, and every `resources/read` and
//!   `prompts/get`, goes to the [`Gate`], which decides it on the policy and
//!   the hook's decision for it and records it; a call it refuses is answered
//!   with error -32001 and never reaches the server;
//! - a message that is not a JSON-RPC request, notification or response, a
//!   request with an id that is not a string or a number, and a request reusing
//!   the id of one the server has not answered yet are answered with -32600.
//!
//! From the server ([`server`]):
//! - a response must answer a request the host sent and the server has not
//!   answered; any other is dropped, so a server cannot slip the host a listing
//!   or a result nobody asked for;
//! - a response that lists tools (`result.tools`) leaves out the tools the pins
//!   hold;
//! - `notifications/tools/list_changed` has the relay read the tools again
//!   itself, so a changed tool is held even when the host never lists again
//!   (a call the relay forwarded before it read the notification reaches the
//!   server, as it would without the relay: the hold starts at the notification);
//! - each request it sends the host (`sampling/createMessage`,
//!   `elicitation/create`, …) is recorded.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::Result;
use serde_json::{Value, json};

use super::tools::ToolPins;

mod frame;
mod host;
mod server;

pub use frame::{pump_host, pump_server};

/// JSON-RPC "invalid params", which MCP uses for an unknown tool.
const UNKNOWN_TOOL: i64 = -32602;
/// A JSON-RPC server error: OpenMoat refused the call.
const REFUSED: i64 = -32001;
/// JSON-RPC "invalid request".
const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC "parse error".
const PARSE_ERROR: i64 = -32700;

/// What an MCP message asks the server to do, for the [`Gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `tools/call`: run a tool.
    Tool,
    /// `resources/read`: read a resource.
    Resource,
    /// `prompts/get`: fill in a prompt.
    Prompt,
}

/// One call the relay is about to pass on.
#[derive(Debug, Clone, Copy)]
pub struct Call<'a> {
    pub method: Method,
    /// The tool's or the prompt's name, or the resource's URI.
    pub name: &'a str,
    /// The tool's or prompt's arguments; `None` when the message has none.
    pub arguments: Option<&'a Value>,
}

/// Decides and records what the relay passes on (`commands/mcp/gate.rs`).
pub trait Gate: Send + Sync {
    /// Decide and record `call`. `held` is why the pins refuse it, if they do:
    /// it is refused then whatever else holds, and still recorded. `Ok(Some)`
    /// is why it is refused; an error refuses it too.
    fn check(&self, call: &Call<'_>, held: Option<&str>) -> Result<Option<String>>;
    /// Record a request the server sent the host; an error has it answered
    /// with an error instead of reaching the host.
    fn server_request(&self, method: &str) -> Result<()>;
}

/// Saves the pins after a listing changed them.
pub type Save = Box<dyn Fn(&ToolPins) -> Result<()> + Send + Sync>;

pub struct Relay {
    server: String,
    state: Mutex<State>,
    gate: Box<dyn Gate>,
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
    /// The ids ([`id_key`]) of the host's requests the server has not
    /// answered yet.
    pending: HashSet<String>,
    /// The listing the relay asked for after the server said its tools changed.
    relist: Option<server::Relist>,
    /// How many listings the relay has asked for, for their ids.
    relists: u64,
}

/// Where a line goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Routed {
    /// To the server.
    Server(String),
    /// To the host.
    Host(String),
    /// Nowhere: why the relay dropped what it read, for its standard error.
    Dropped(String),
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
        gate: Box<dyn Gate>,
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
                pending: HashSet::new(),
                relist: None,
                relists: 0,
            }),
            gate,
            save,
            now_ms,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One line from the host.
    pub fn host_line(&self, line: &str) -> Vec<Routed> {
        let Some(message) = read(line) else {
            if line.trim().is_empty() {
                return Vec::new();
            }
            // A line the relay cannot read is not passed on: a server's own
            // parser may read it (a lone surrogate, an out-of-range number),
            // and a `tools/call` in it would reach the server unchecked.
            let why = "OpenMoat's MCP proxy cannot read this message, so it is not passed on";
            return vec![Routed::Host(written(&error(
                &Value::Null,
                PARSE_ERROR,
                why,
            )))];
        };
        let Value::Array(batch) = message else {
            return match self.on_host(message) {
                host::Outcome::Forward(m) => vec![Routed::Server(written(&m))],
                host::Outcome::Reply(r) => vec![Routed::Host(written(&r))],
                host::Outcome::Drop => Vec::new(),
            };
        };
        if batch.is_empty() {
            let reply = error(
                &Value::Null,
                INVALID_REQUEST,
                "an empty batch is not a request",
            );
            return vec![Routed::Host(written(&reply))];
        }
        let (mut forward, mut replies) = (Vec::new(), Vec::new());
        for message in batch {
            match self.on_host(message) {
                host::Outcome::Forward(m) => forward.push(m),
                host::Outcome::Reply(r) => replies.push(r),
                host::Outcome::Drop => {}
            }
        }
        let mut out = Vec::new();
        if !forward.is_empty() {
            out.push(Routed::Server(written(&Value::Array(forward))));
        }
        if !replies.is_empty() {
            out.push(Routed::Host(written(&Value::Array(replies))));
        }
        out
    }

    /// One line from the server.
    pub fn server_line(&self, line: &str) -> Vec<Routed> {
        let Some(message) = read(line) else {
            if line.trim().is_empty() {
                return Vec::new();
            }
            // The host's reader may take what this one refuses (a lone
            // surrogate, `NaN`): passed on, an unfiltered listing would reach it.
            return vec![Routed::Dropped(
                "a line from the server that is not JSON OpenMoat reads".to_owned(),
            )];
        };
        let Value::Array(batch) = message else {
            let mut out = Vec::new();
            if let Some(m) = self.on_server(message, &mut out) {
                out.push(Routed::Host(written(&m)));
            }
            return out;
        };
        let mut out = Vec::new();
        let forward: Vec<Value> = batch
            .into_iter()
            .filter_map(|m| self.on_server(m, &mut out))
            .collect();
        if !forward.is_empty() {
            out.push(Routed::Host(written(&Value::Array(forward))));
        }
        out
    }
}

/// `line` as one JSON value, or `None`.
fn read(line: &str) -> Option<Value> {
    serde_json::from_str::<Value>(line).ok()
}

/// `value` as the one line the relay sends: compact JSON, with U+0085,
/// U+2028 and U+2029 escaped as well as the control characters JSON escapes,
/// so no reader that splits lines on any of them (Python's `splitlines`)
/// sees two messages where the relay checked one.
pub(super) fn written(value: &Value) -> String {
    let mut out = Vec::new();
    let mut writer = serde_json::Serializer::with_formatter(&mut out, LineFormatter);
    match serde::Serialize::serialize(value, &mut writer) {
        Ok(()) => String::from_utf8(out).unwrap_or_else(|_| value.to_string()),
        Err(_) => value.to_string(),
    }
}

/// `serde_json`'s compact form, escaping the line breaks JSON leaves raw.
struct LineFormatter;

impl serde_json::ser::Formatter for LineFormatter {
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut rest = fragment;
        while let Some(at) = rest.find(['\u{85}', '\u{2028}', '\u{2029}']) {
            writer.write_all(&rest.as_bytes()[..at])?;
            let Some(c) = rest[at..].chars().next() else {
                break;
            };
            write!(writer, "\\u{:04x}", u32::from(c))?;
            rest = &rest[at + c.len_utf8()..];
        }
        writer.write_all(rest.as_bytes())
    }
}

/// A JSON-RPC request id as the relay matches responses to it: the exact
/// value, so `2` and `"2"` are two ids.
fn id_key(id: &Value) -> String {
    id.to_string()
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests;
