//! What the relay does with each message from the host.

use serde_json::{Map, Value};

use super::{Call, INVALID_REQUEST, Method, REFUSED, Relay, UNKNOWN_TOOL, error, id_key, server};

/// The most requests the server may leave unanswered at once; a host keeps a
/// few in flight, and the set must not grow without end.
const MAX_PENDING: usize = 4096;

/// The methods the relay checks; a request is checked only when its method is
/// one of these exactly.
const CHECKED: [&str; 3] = ["tools/call", "resources/read", "prompts/get"];

/// Whether `method` reads as a checked method in another case or with
/// spaces: a server that matches methods loosely would run it unchecked.
fn is_near_miss(method: &str) -> bool {
    !CHECKED.contains(&method)
        && CHECKED
            .iter()
            .any(|checked| method.trim().eq_ignore_ascii_case(checked))
}

/// Where one message from the host goes.
pub(super) enum Outcome {
    /// To the server, as the relay read it.
    Forward(Value),
    /// Back to the host: the relay answered it.
    Reply(Value),
    /// Nowhere: a refused notification, which gets no answer.
    Drop,
}

impl Relay {
    pub(super) fn on_host(&self, message: Value) -> Outcome {
        let Value::Object(fields) = &message else {
            return Outcome::Reply(error(
                &Value::Null,
                INVALID_REQUEST,
                "not a JSON-RPC message (an object)",
            ));
        };
        let answers = fields.contains_key("result") || fields.contains_key("error");
        let id = fields.get("id");
        match (fields.get("method"), answers, id) {
            (Some(Value::String(method)), false, _) => self.request(method, fields, id, &message),
            // The host's answer to a request the server sent it.
            (None, true, Some(_)) => Outcome::Forward(message),
            (_, _, Some(id)) => Outcome::Reply(error(
                id,
                INVALID_REQUEST,
                "neither a JSON-RPC request, a notification nor a response",
            )),
            (_, _, None) => Outcome::Drop,
        }
    }

    fn request(
        &self,
        method: &str,
        fields: &Map<String, Value>,
        id: Option<&Value>,
        message: &Value,
    ) -> Outcome {
        if let Some(id) = id
            && let Some(why) = self.bad_id(id)
        {
            let shown = if id.is_string() || id.is_number() {
                id
            } else {
                &Value::Null
            };
            return Outcome::Reply(error(shown, INVALID_REQUEST, &why));
        }
        if is_near_miss(method) {
            let why = format!("`{method}` is not a method; MCP's is spelled exactly");
            return match id {
                Some(id) => Outcome::Reply(error(id, INVALID_REQUEST, &why)),
                None => Outcome::Drop,
            };
        }
        let params = fields.get("params");
        let refused = match method {
            "tools/call" => self.tool_call(params),
            "resources/read" => {
                let uri = params.and_then(|p| p.get("uri")).and_then(Value::as_str);
                self.gated(Method::Resource, uri.unwrap_or(""), None, None)
            }
            "prompts/get" => {
                let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
                let arguments = params.and_then(|p| p.get("arguments"));
                self.gated(Method::Prompt, name.unwrap_or(""), arguments, None)
            }
            "notifications/cancelled" => {
                // The server may never answer a cancelled request.
                if let Some(cancelled) = params.and_then(|p| p.get("requestId")) {
                    self.state().pending.remove(&id_key(cancelled));
                }
                None
            }
            _ => None,
        };
        match (refused, id) {
            (None, Some(id)) => {
                self.state().pending.insert(id_key(id));
                Outcome::Forward(message.clone())
            }
            (None, None) => Outcome::Forward(message.clone()),
            (Some((code, why)), Some(id)) => Outcome::Reply(error(id, code, &why)),
            (Some(_), None) => Outcome::Drop,
        }
    }

    /// Why a request may not use `id`: MCP ids are strings or numbers; the
    /// relay's own listings use ids of their own; and an id the server has not
    /// answered yet would leave the relay unable to tell the two answers apart.
    fn bad_id(&self, id: &Value) -> Option<String> {
        if !(id.is_string() || id.is_number()) {
            return Some("a request id must be a string or a number".to_owned());
        }
        if server::is_relay_id(id) {
            return Some("this request id is reserved for OpenMoat's MCP proxy".to_owned());
        }
        let state = self.state();
        if state.pending.contains(&id_key(id)) {
            return Some("this request id is already in use by an unanswered request".to_owned());
        }
        if state.pending.len() >= MAX_PENDING {
            return Some(format!(
                "more than {MAX_PENDING} requests are waiting for the server"
            ));
        }
        None
    }

    /// `tools/call`: the pins first, then the gate.
    fn tool_call(&self, params: Option<&Value>) -> Option<(i64, String)> {
        let tool = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = params.and_then(|p| p.get("arguments"));
        if let Some(arguments) = arguments
            && !(arguments.is_object() || arguments.is_null())
        {
            return Some((
                UNKNOWN_TOOL,
                "the arguments of a tool call must be an object".into(),
            ));
        }
        let held = self.refusal(tool);
        self.gated(Method::Tool, tool, arguments, held)
    }

    /// The gate's answer: `None` to pass the call on, else the error to answer.
    fn gated(
        &self,
        method: Method,
        name: &str,
        arguments: Option<&Value>,
        held: Option<String>,
    ) -> Option<(i64, String)> {
        let call = Call {
            method,
            name,
            arguments,
        };
        let code = if held.is_some() {
            UNKNOWN_TOOL
        } else {
            REFUSED
        };
        match self.gate.check(&call, held.as_deref()) {
            Ok(None) if held.is_none() => None,
            Ok(None) => held.map(|why| (code, why)),
            Ok(Some(why)) => Some((code, why)),
            Err(e) => Some((
                code,
                format!("OpenMoat cannot decide or record this call ({e:#}), so it is refused"),
            )),
        }
    }

    /// Why the pins refuse a call of `tool`, if they do.
    fn refusal(&self, tool: &str) -> Option<String> {
        let mut state = self.state();
        let server = &self.server;
        if let Some(why) = &state.broken {
            return Some(format!(
                "OpenMoat cannot save the tool definitions of MCP server `{server}` ({why}), \
                 so it refuses its tool calls"
            ));
        }
        if self.relisting(&mut state) {
            return Some(format!(
                "MCP server `{server}` said its tools changed, and OpenMoat is reading them \
                 again; try the call again in a moment"
            ));
        }
        // Before the first listing too, whatever the policy trusts: a tool
        // with no pin is one nobody accepted.
        if state.pins.is_held(tool) || !state.pins.tools.contains_key(tool) {
            return Some(format!(
                "OpenMoat holds tool `{tool}` of MCP server `{server}`: its description or \
                 input schema is not the one a person accepted, or it is new. Run \
                 `openmoat mcp accept {server}` in a terminal to review it"
            ));
        }
        None
    }
}
