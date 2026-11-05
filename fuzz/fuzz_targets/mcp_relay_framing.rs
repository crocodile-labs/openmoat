//! `moat mcp proxy` sits between an agent host and an MCP server it does not
//! trust (ADR-045): both write it any bytes. The relay's framing and JSON-RPC
//! checks must not panic, and what it passes on must be one well-formed line
//! per message: a request or notification with a method, or a response that
//! answers a request the other side sent and is still waiting for.
//!
//! The input is a script: segments split at a NUL byte, each sent whole by
//! the host (first byte even) or the server (odd), through the relay's own
//! line reader (`pump_host`, `pump_server`). The first byte's bits choose
//! whether the policy trusts a server's first listing and whether the gate
//! refuses calls.

#![no_main]

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::{Arc, Mutex, PoisonError};

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// The relay's files as the CLI ships them. `moat` is a binary crate, and the
/// relay needs only `anyhow`, `serde`, `serde_json`, `openmoat-hosts` and the
/// pins type from its parent module, which [`mcp::tools`] stands in for. The
/// `path` makes this module stand for the CLI's `src/mcp/` directory, so
/// `relay` and its own `frame`, `host` and `server` are the CLI's files.
#[path = "../../crates/openmoat-cli/src/mcp"]
mod mcp {
    /// A stand-in for `crates/openmoat-cli/src/mcp/tools.rs`, whose real
    /// `ToolPins` reads and writes files and hashes with the CLI's helpers.
    /// It keeps the four things the relay uses, with the same meaning: a
    /// first listing under `trust_first_sight` is pinned as it is; otherwise
    /// a tool with no pin, or listed differently from its pin, is held and
    /// hidden. Pin digests are the entry's compact JSON instead of a hash, so
    /// this fuzzes the relay's framing and routing, not the pin store.
    pub mod tools {
        use std::collections::{BTreeMap, BTreeSet};

        use serde_json::Value;

        #[derive(Debug, Default)]
        pub struct ToolPins {
            pub tools: BTreeMap<String, String>,
            held: BTreeMap<String, String>,
        }

        #[derive(Debug, Default)]
        pub struct Listing {
            pub hidden: BTreeSet<String>,
            pub changed: bool,
        }

        impl ToolPins {
            pub fn new(_server: &str) -> Self {
                Self::default()
            }

            pub fn is_held(&self, tool: &str) -> bool {
                self.held.contains_key(tool)
            }

            pub fn list(&mut self, tools: &[Value], first: bool, _now_ms: i64) -> Listing {
                let mut listing = Listing::default();
                let listed = tools.iter().filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_owned();
                    Some((name, t.to_string()))
                });
                for (name, digest) in listed {
                    if first && !self.tools.contains_key(&name) {
                        self.tools.insert(name.clone(), digest.clone());
                        listing.changed = true;
                    }
                    if self.tools.get(&name) == Some(&digest) {
                        listing.changed |= self.held.remove(&name).is_some();
                    } else {
                        listing.changed |= self.held.insert(name.clone(), digest).is_none();
                        listing.hidden.insert(name);
                    }
                }
                listing
            }
        }
    }

    // rustfmt would follow the file's `#[cfg(test)] mod tests;` from here and
    // not find it; the file is formatted as part of the main workspace.
    #[rustfmt::skip]
    pub mod relay;
}

use mcp::relay::{Call, Gate, Method, Relay, pump_host, pump_server, refuse_all};

/// Allows or refuses every call, and remembers each one it was asked about.
struct FuzzGate {
    refuse: bool,
    checked: Arc<Mutex<Vec<(Method, String)>>>,
}

impl Gate for FuzzGate {
    fn check(&self, call: &Call<'_>, _held: Option<&str>) -> anyhow::Result<Option<String>> {
        let _ = call.arguments;
        self.checked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((call.method, call.name.to_owned()));
        Ok(self.refuse.then(|| "refused".to_owned()))
    }

    fn server_request(&self, _method: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The messages of one line the relay wrote: a batch's elements, or itself.
fn messages(line: &str) -> Vec<Value> {
    // Escaped as JSON escapes them, and the three line breaks JSON leaves
    // raw: no reader splitting lines on any of them sees two messages.
    assert!(
        !line.contains(['\r', '\u{85}', '\u{2028}', '\u{2029}']),
        "{line:?}"
    );
    let value: Value = serde_json::from_str(line).expect("the relay writes JSON");
    match value {
        Value::Array(batch) => {
            assert!(!batch.is_empty(), "{line}");
            batch
        }
        one => vec![one],
    }
}

fn written(out: &Mutex<Option<Vec<u8>>>) -> Vec<String> {
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    let bytes = out.as_mut().map_or_default(std::mem::take);
    let text = String::from_utf8(bytes).expect("the relay writes UTF-8");
    assert!(text.is_empty() || text.ends_with('\n'), "{text:?}");
    text.lines().map(str::to_owned).collect()
}

fn is_request(m: &serde_json::Map<String, Value>) -> bool {
    m.get("method").is_some_and(Value::is_string)
        && !m.contains_key("result")
        && !m.contains_key("error")
}

fn is_response(m: &serde_json::Map<String, Value>) -> bool {
    !m.contains_key("method") && (m.contains_key("result") || m.contains_key("error"))
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, script)) = data.split_first() else {
        return;
    };
    let checked = Arc::new(Mutex::new(Vec::new()));
    let gate = FuzzGate {
        refuse: flags & 2 != 0,
        checked: Arc::clone(&checked),
    };
    let relay = Relay::new(
        "fuzz",
        None,
        flags & 1 != 0,
        Box::new(gate),
        Box::new(|_| Ok(())),
        || 0,
    );
    let server = Mutex::new(Some(Vec::new()));
    let host = Mutex::new(Some(Vec::new()));
    let note = |_: &str| {};
    // The ids of the host's requests the server was sent and has not answered.
    let mut waiting: HashSet<String> = HashSet::new();
    for segment in script.split(|b| *b == 0) {
        let Some((&who, bytes)) = segment.split_first() else {
            continue;
        };
        let from_host = who & 1 == 0;
        if from_host && who & 0x80 != 0 {
            // The proxy refusing a server it may not start: requests only
            // get an error with their own id.
            let refused = Mutex::new(Some(Vec::new()));
            let _ = refuse_all(Cursor::new(bytes), &refused, "not started");
            for line in written(&refused) {
                for m in messages(&line) {
                    assert!(m.get("error").is_some() && m.get("id").is_some(), "{m}");
                }
            }
            continue;
        }
        let before = checked.lock().unwrap_or_else(PoisonError::into_inner).len();
        let _ = if from_host {
            pump_host(&relay, Cursor::new(bytes), &server, &host, &note)
        } else {
            pump_server(&relay, Cursor::new(bytes), &server, &host, &note)
        };
        let gated = checked.lock().unwrap_or_else(PoisonError::into_inner)[before..].to_vec();
        for line in written(&server) {
            for m in messages(&line) {
                let Value::Object(m) = m else {
                    panic!("the server was sent a message that is not an object: {line}");
                };
                let id = m.get("id").map(Value::to_string);
                if is_request(&m) {
                    let method = m.get("method").and_then(Value::as_str).unwrap_or_default();
                    if let Some(id) = &id {
                        // The relay's own listings use ids a host may not.
                        let own = m
                            .get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|i| i.starts_with("openmoat-relay-"));
                        assert!(own || waiting.insert(id.clone()), "id reused: {line}");
                        assert!(
                            m.get("id").is_some_and(|i| i.is_string() || i.is_number()),
                            "{line}"
                        );
                    }
                    if method == "notifications/cancelled"
                        && let Some(cancelled) = m.get("params").and_then(|p| p.get("requestId"))
                    {
                        waiting.remove(&cancelled.to_string());
                    }
                    let kind = match method {
                        "tools/call" => Some(Method::Tool),
                        "resources/read" => Some(Method::Resource),
                        "prompts/get" => Some(Method::Prompt),
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        assert!(from_host, "the relay made up a call: {line}");
                        assert!(gated.iter().any(|(k, _)| *k == kind), "ungated: {line}");
                    }
                    assert!(
                        !["tools/call", "resources/read", "prompts/get"]
                            .iter()
                            .any(|c| method != *c && method.trim().eq_ignore_ascii_case(c)),
                        "near miss passed: {line}"
                    );
                } else if is_response(&m) {
                    // The host's answer to one of the server's requests, or
                    // the relay's own refusal of one.
                    assert!(id.is_some(), "a response without an id: {line}");
                } else {
                    panic!("neither request nor response sent to the server: {line}");
                }
            }
        }
        for line in written(&host) {
            for m in messages(&line) {
                let Value::Object(m) = m else {
                    panic!("the host was sent a message that is not an object: {line}");
                };
                let id = m.get("id");
                if is_request(&m) {
                    assert!(!from_host, "a host request came back as one: {line}");
                } else if is_response(&m) {
                    let id = id.expect("a response has an id");
                    let unaddressed_error = id.is_null() && m.contains_key("error");
                    if !from_host && !unaddressed_error {
                        // A server's response reaches the host only when it
                        // answers a request the host is waiting for.
                        assert!(waiting.remove(&id.to_string()), "unasked: {line}");
                    }
                } else {
                    panic!("neither request nor response sent to the host: {line}");
                }
            }
        }
    }
});
