//! The server's `initialize` answer and its prompt and resource listings,
//! checked against the pins before the host reads them (ADR-069): held
//! `instructions` never reach the host, a held `serverInfo` is the accepted
//! one, and a held listing entry is left out.

use serde_json::{Value, json};

use super::{Relay, State};
use crate::mcp::tools::surface::{ANY_VERSION, Kind, is_version_like};

impl Relay {
    /// Check `message` against the pins when it answers the host's
    /// `initialize` request `id`, or lists prompts, resources or templates.
    pub(super) fn filter_surface(&self, message: &mut Value, id: &str) {
        let mut state = self.state();
        if state.initialize.as_deref() == Some(id) {
            state.initialize = None;
            if let Some(result) = message.get_mut("result").filter(|r| r.is_object()) {
                self.introduce(&mut state, result);
            }
        }
        for kind in Kind::ALL {
            let Some(Value::Array(entries)) = message.pointer_mut(kind.pointer()) else {
                continue;
            };
            let trust = state.pins.trusts(Some(kind), state.trust_unseen);
            let listed = state
                .pins
                .surface_mut()
                .list(kind, entries, trust, (self.now_ms)());
            if listed.changed {
                self.save_pins(&mut state);
            }
            // An entry without a string key has no pin to check it against.
            entries.retain(|e| {
                e.get(kind.key())
                    .and_then(Value::as_str)
                    .is_some_and(|k| !listed.hidden.contains(k))
            });
        }
    }

    /// The `initialize` `result`: the accepted instructions and server
    /// information pass and are kept for the sessions this proxy serves; held
    /// ones are taken out.
    fn introduce(&self, state: &mut State, result: &mut Value) {
        let trust = state.pins.trusts(None, state.trust_unseen);
        let capabilities = result.get("capabilities").cloned().unwrap_or(Value::Null);
        let introduced = state
            .pins
            .surface_mut()
            .introduce(result, trust, (self.now_ms)());
        if trust {
            state.pins.surface_mut().unlisted_seen(&capabilities);
        }
        if introduced.changed {
            self.save_pins(state);
        }
        let Value::Object(fields) = result else {
            return;
        };
        if introduced.held {
            fields.remove("instructions");
            // Only a version number of the answer is kept: other text in it
            // is what the pins hold.
            let version = fields
                .get("serverInfo")
                .and_then(|i| i.get("version"))
                .and_then(Value::as_str)
                .filter(|v| is_version_like(v))
                .map(|v| Value::String(v.to_owned()));
            let mut info = introduced
                .accepted_info
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({"name": self.server, "version": "0"}));
            if info["version"] == ANY_VERSION {
                info["version"] = version.unwrap_or_else(|| Value::String("0".to_owned()));
            }
            fields.insert("serverInfo".to_owned(), info);
            return;
        }
        if let Some(Value::String(text)) = fields.get("instructions") {
            self.gate.instructions(text);
        }
    }

    /// Why the pins refuse `prompts/get` of `name`, if they do: a prompt no
    /// person accepted, or one held, is not filled in.
    pub(super) fn prompt_refusal(&self, name: &str) -> Option<String> {
        let state = self.state();
        let server = &self.server;
        if let Some(why) = &state.broken {
            return Some(format!(
                "OpenMoat cannot save the definitions of MCP server `{server}` ({why}), so it \
                 refuses its prompts"
            ));
        }
        if !state.pins.surface().prompt_held(name) {
            return None;
        }
        Some(format!(
            "OpenMoat holds prompt `{name}` of MCP server `{server}`: its description or \
             arguments are not the ones a person accepted, or it is new. Run `openmoat mcp \
             accept {server}` in a terminal to review it"
        ))
    }
}
