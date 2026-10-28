//! What the relay does with each message from the server.

use serde_json::{Map, Value};

use super::{REFUSED, Relay, Routed, State, error, id_key, written};

/// The ids of the listings the relay asks for begin with this; a host request
/// may not use one.
const RELAY_ID_PREFIX: &str = "openmoat-relay-";
/// How long calls wait for a listing the relay asked for; a server that never
/// answers it gets its calls back after this, checked against the pins it had.
const RELIST_WAIT_MS: i64 = 10_000;
/// The most pages of one listing the relay reads.
const MAX_RELIST_PAGES: u32 = 100;
/// Server requests recorded only by their effect on the session, not one by one.
const UNRECORDED_REQUESTS: &[&str] = &["ping"];

/// A listing the relay asked for itself.
pub(super) struct Relist {
    /// The id of the page asked for last.
    id: String,
    /// When the listing was asked for.
    since_ms: i64,
    /// How many pages were asked for.
    pages: u32,
}

/// Whether `id` is one the relay uses for its own requests.
pub(super) fn is_relay_id(id: &Value) -> bool {
    id.as_str().is_some_and(|s| s.starts_with(RELAY_ID_PREFIX))
}

impl Relay {
    /// What reaches the host of `message`, if anything; what goes to the
    /// server instead, and why anything was dropped, is added to `out`.
    pub(super) fn on_server(&self, mut message: Value, out: &mut Vec<Routed>) -> Option<Value> {
        let Value::Object(fields) = &message else {
            out.push(dropped(
                "a message from the server that is not a JSON-RPC object",
            ));
            return None;
        };
        let answers = fields.contains_key("result") || fields.contains_key("error");
        match (fields.get("method"), answers) {
            (Some(Value::String(method)), false) => {
                self.server_message(method, fields, out).then_some(message)
            }
            (None, true) => {
                let id = fields.get("id").cloned().unwrap_or(Value::Null);
                if self.response_of(&id, fields, out) {
                    self.filter_listing(&mut message);
                    Some(message)
                } else {
                    None
                }
            }
            _ => {
                out.push(dropped(
                    "a message from the server that is neither a request, a notification nor \
                     a response",
                ));
                None
            }
        }
    }

    /// Whether a request or notification from the server reaches the host; a
    /// request that cannot be recorded is answered here instead.
    fn server_message(
        &self,
        method: &str,
        fields: &Map<String, Value>,
        out: &mut Vec<Routed>,
    ) -> bool {
        if method == "notifications/tools/list_changed" {
            let mut state = self.state();
            if !self.relisting(&mut state)
                && let Some(ask) = self.ask_listing(&mut state, None)
            {
                out.push(ask);
            }
            return true;
        }
        let Some(id) = fields.get("id") else {
            return true;
        };
        if UNRECORDED_REQUESTS.contains(&method) {
            return true;
        }
        let Err(e) = self.gate.server_request(method) else {
            return true;
        };
        let why = format!("OpenMoat cannot record this request ({e:#}), so it is refused");
        out.push(Routed::Server(written(&error(id, REFUSED, &why))));
        out.push(dropped(&format!("the server's `{method}` request: {e:#}")));
        false
    }

    /// Whether the response with `id` reaches the host: it answers a request
    /// the host sent and the server had not answered yet. A response to the
    /// relay's own listing is read here and goes no further.
    fn response_of(&self, id: &Value, fields: &Map<String, Value>, out: &mut Vec<Routed>) -> bool {
        let mut state = self.state();
        if state
            .relist
            .as_ref()
            .is_some_and(|r| id.as_str() == Some(&r.id))
        {
            self.read_relisting(&mut state, fields, out);
            return false;
        }
        // An error about a message the server could not read names no request.
        if id.is_null() && fields.contains_key("error") {
            return true;
        }
        if state.pending.remove(&id_key(id)) {
            return true;
        }
        out.push(dropped(&format!(
            "a response from the server with id {id}, which answers no request the host is \
             waiting for"
        )));
        false
    }

    /// Leave the held tools out of a response that lists tools; a listing
    /// that changes the pins is saved. Every response with a tools array
    /// counts, whatever request it answers.
    fn filter_listing(&self, message: &mut Value) {
        let Some(Value::Array(tools)) = message.pointer_mut("/result/tools") else {
            return;
        };
        let mut state = self.state();
        let hidden = self.list(&mut state, tools);
        // An entry without a string name has no pin to check it against, and
        // a host may still read one: it is dropped.
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| !hidden.contains(n))
        });
    }

    /// Check one listing against the pins, saving them when it changed them;
    /// the names to hide.
    fn list(&self, state: &mut State, tools: &[Value]) -> std::collections::BTreeSet<String> {
        let first = state.first;
        let listing = state.pins.list(tools, first, (self.now_ms)());
        state.first = false;
        if listing.changed
            && let Err(e) = (self.save)(&state.pins)
        {
            state.broken = Some(format!("{e:#}"));
        }
        listing.hidden
    }

    /// Whether the relay is waiting for a listing it asked for; one it has
    /// waited too long for is given up.
    pub(super) fn relisting(&self, state: &mut State) -> bool {
        let now = (self.now_ms)();
        match &state.relist {
            Some(relist) if now.saturating_sub(relist.since_ms) <= RELIST_WAIT_MS => true,
            Some(_) => {
                state.relist = None;
                false
            }
            None => false,
        }
    }

    /// Ask the server for its tools (the page after `cursor`): the request to
    /// send, `None` past the page limit.
    fn ask_listing(&self, state: &mut State, cursor: Option<&str>) -> Option<Routed> {
        let pages = state.relist.as_ref().map_or(0, |r| r.pages);
        if pages >= MAX_RELIST_PAGES {
            state.relist = None;
            return None;
        }
        state.relists += 1;
        let id = format!("{RELAY_ID_PREFIX}{}", state.relists);
        let since_ms = state
            .relist
            .as_ref()
            .map_or_else(|| (self.now_ms)(), |r| r.since_ms);
        let request = openmoat_hosts::mcp_tools_list_request(&id, cursor);
        state.relist = Some(Relist {
            id,
            since_ms,
            pages: pages + 1,
        });
        Some(Routed::Server(written(&request)))
    }

    /// The server's answer to the relay's own listing: held tools are held
    /// as in any listing, and the next page asked for.
    fn read_relisting(
        &self,
        state: &mut State,
        fields: &Map<String, Value>,
        out: &mut Vec<Routed>,
    ) {
        let result = fields.get("result");
        let Some(Value::Array(tools)) = result.and_then(|r| r.get("tools")) else {
            // An error, or no list: the pins decide as before.
            state.relist = None;
            return;
        };
        self.list(state, tools);
        match result
            .and_then(|r| r.get("nextCursor"))
            .and_then(Value::as_str)
        {
            Some(cursor) => {
                if let Some(ask) = self.ask_listing(state, Some(cursor)) {
                    out.push(ask);
                }
            }
            None => state.relist = None,
        }
    }
}

fn dropped(why: &str) -> Routed {
    Routed::Dropped(format!("dropped {why}"))
}
