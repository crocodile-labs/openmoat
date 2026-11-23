//! MCP 2026-07-28 (ADR-114): which revision the host speaks, the server's
//! `server/discover` answer, and the identity each of its results names.
//!
//! The revision is read from each message, never fixed for the process: a
//! request whose `_meta` names `io.modelcontextprotocol/protocolVersion` is
//! 2026-07-28 (<https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>),
//! `initialize` is an earlier one, and a server may serve both at once. Every
//! answer the host gets is checked against the pins of what it is: an
//! `initialize` answer as ADR-069 says, a `server/discover` answer and each
//! result's `serverInfo` here. So a server that shows one revision a clean
//! face and the other a new one is held on the one the host reads.

use serde_json::{Value, json};

use super::{Relay, State};
use crate::mcp::tools::surface::{ANY_VERSION, SERVER_INFO, is_version_like};

/// The `_meta` key that marks a 2026-07-28 request.
const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

impl Relay {
    /// Note the revision the host's `method` request speaks.
    pub(super) fn note_revision(&self, method: &str, params: Option<&Value>) {
        let version = params
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(PROTOCOL_VERSION));
        let mut state = self.state();
        if let Some(version) = version {
            state.spoken.modern = true;
            state.spoken.protocol = Some(version.clone());
        }
        state.spoken.legacy |= method == "initialize";
    }

    /// `request`, one the relay sends itself, with the `_meta` a 2026-07-28
    /// server requires on every request when the host speaks that revision.
    pub(super) fn with_revision(state: &State, mut request: Value) -> Value {
        if let Some(version) = &state.spoken.protocol
            && let Value::Object(fields) = &mut request
        {
            let params = fields.entry("params").or_insert_with(|| json!({}));
            if let Value::Object(params) = params {
                params.insert(
                    "_meta".to_owned(),
                    json!({PROTOCOL_VERSION: version,
                        "io.modelcontextprotocol/clientCapabilities": {}}),
                );
            }
        }
        request
    }

    /// Why a server request reaches no host: a host that speaks only
    /// 2026-07-28 gets none, since a server of that revision asks through a
    /// result's `inputRequests` (stdio binding: "The server MUST NOT write
    /// JSON-RPC requests to stdout").
    pub(super) fn no_requests(&self) -> Option<String> {
        let state = self.state();
        (state.spoken.modern && !state.spoken.legacy).then(|| {
            "the agent speaks MCP 2026-07-28, under which a server sends no requests (it asks \
             through a result's `inputRequests`), so OpenMoat does not pass this one on"
                .to_owned()
        })
    }

    /// Why the pins refuse every call of the server, if they do: the
    /// identity its results give is not the accepted one.
    pub(super) fn server_hold(&self, state: &State) -> Option<String> {
        let server = &self.server;
        if let Some(why) = &state.identity_changed {
            return Some(why.clone());
        }
        state.pins.surface().identity_held().then(|| {
            format!(
                "OpenMoat holds MCP server `{server}`: the server information its results give \
                 is not the one a person accepted. Run `openmoat mcp accept {server}` in a \
                 terminal to review it"
            )
        })
    }

    /// Check `message`, the server's answer to the host's request `id`:
    /// a `server/discover` answer against its pins, and the identity any
    /// result names.
    pub(super) fn filter_modern(&self, message: &mut Value, id: &str) {
        let mut state = self.state();
        // Forgotten whatever the answer, an error included.
        let discovery = state.discovers.remove(id);
        let Some(result) = message.get_mut("result").filter(|r| r.is_object()) else {
            return;
        };
        if discovery {
            self.discovered(&mut state, result);
        }
        self.check_identity(&mut state, result);
    }

    /// The `server/discover` `result`: as an `initialize` answer is, an
    /// accepted one passes and its instructions are kept for the sessions
    /// served; a held one reaches the host as the accepted one, or without
    /// instructions.
    fn discovered(&self, state: &mut State, result: &mut Value) {
        let trust = {
            let surface = state.pins.surface();
            (state.trust_unseen || surface.adopt) && surface.modern_unseen(false)
        };
        let capabilities = result.get("capabilities").cloned().unwrap_or(Value::Null);
        let found = state
            .pins
            .surface_mut()
            .discover(result, trust, (self.now_ms)());
        if trust {
            state.pins.surface_mut().unlisted_seen(&capabilities);
        }
        if found.changed {
            self.save_pins(state);
        }
        let Value::Object(fields) = result else {
            return;
        };
        if !found.held {
            if let Some(Value::String(text)) = fields.get("instructions") {
                self.gate.instructions(text);
            }
            return;
        }
        fields.remove("instructions");
        if let Some(Value::Object(accepted)) = found.accepted_info {
            fields.retain(|key, _| {
                matches!(
                    key.as_str(),
                    "resultType" | "ttlMs" | "cacheScope" | "_meta"
                )
            });
            fields.extend(accepted);
        }
    }

    /// Check the identity `result` names, if it names one: once it differs
    /// from the first this process saw, or from the accepted one, the server
    /// is held and the host is given the accepted identity in its place.
    pub(super) fn check_identity(&self, state: &mut State, result: &mut Value) {
        let Some(info) = result.pointer(&format!("/_meta/{}", escape(SERVER_INFO))) else {
            return;
        };
        let info = info.clone();
        match &state.identity_seen {
            None => state.identity_seen = Some(info.clone()),
            Some(first) if *first != info && state.identity_changed.is_none() => {
                let server = &self.server;
                state.identity_changed = Some(format!(
                    "MCP server `{server}` named itself {} in one result and {} in a later one; \
                     OpenMoat refuses its calls until it is started again",
                    crate::render::clean(&first.to_string()),
                    crate::render::clean(&info.to_string()),
                ));
            }
            Some(_) => {}
        }
        let trust = {
            let surface = state.pins.surface();
            (state.trust_unseen || surface.adopt) && surface.modern_unseen(true)
        };
        let found = state
            .pins
            .surface_mut()
            .identity(&info, trust, (self.now_ms)());
        if found.changed {
            self.save_pins(state);
        }
        if found.held || state.identity_changed.is_some() {
            let mut shown = found
                .accepted
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({"name": self.server, "version": "0"}));
            if shown["version"] == ANY_VERSION {
                // Only a version number of the result is kept, as for
                // `initialize`: other text in it is what the pins hold.
                let version = info
                    .get("version")
                    .and_then(Value::as_str)
                    .filter(|v| is_version_like(v))
                    .unwrap_or("0");
                shown["version"] = Value::String(version.to_owned());
            }
            if let Some(Value::Object(meta)) = result.get_mut("_meta") {
                meta.insert(SERVER_INFO.to_owned(), shown);
            }
        }
    }
}

/// `key` as a JSON pointer token.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}
