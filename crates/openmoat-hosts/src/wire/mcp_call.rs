//! One MCP tool call as both ends of OpenMoat see it: the hook, which decides
//! the call before the host sends it, and `openmoat mcp proxy`, which relays it
//! to the server (ADR-045). The proxy passes a call on only when it matches a
//! decision the hook made, so both must read the arguments to the same text.

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

/// `value` as compact JSON with every object's keys sorted: the same text for
/// the same value, whatever order a host or a server wrote the keys in.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// The arguments of an MCP `tools/call` as [`canonical_json`]; a call with no
/// arguments, or `null` ones, has `{}`, which is what a host's hook payload
/// shows for it.
#[must_use]
pub fn mcp_call_arguments(arguments: Option<&Value>) -> String {
    match arguments {
        None | Some(Value::Null) => "{}".to_owned(),
        Some(value) => canonical_json(value),
    }
}

/// The arguments a hook payload gives the MCP call `action` names, for
/// [`crate::HookRequest::mcp_arguments`]. `input` is the tool's input as the
/// host sent it (a JSON string, as Cursor sends it, is parsed). `None` for an
/// action that is not an MCP call, or input that is not JSON.
pub(crate) fn hook_arguments(action: Option<&Action>, input: &Value) -> Option<String> {
    let Some(Action::McpTool { name, .. }) = action else {
        return None;
    };
    let arguments = super::mcp::arguments(name, input).ok()?;
    Some(mcp_call_arguments(Some(&arguments)))
}

/// The action of `tools/call` of `name` (`mcp__<server>__<tool>`) with
/// `arguments`, as the hook decides an MCP call: every path and URL the
/// arguments name by key becomes an `fs` or `net` resource of the call.
///
/// # Errors
/// When the arguments name more paths and URLs than are checked.
pub fn mcp_call_action(name: &str, arguments: &Value) -> Result<Action, HostError> {
    let none = Value::Object(serde_json::Map::new());
    let arguments = if arguments.is_null() {
        &none
    } else {
        arguments
    };
    super::mcp::action(name, arguments)
}

/// The action of `resources/read` of `uri` from MCP server `server`: a
/// `file:` URI reads the file it names, a URI with a scheme that connects
/// somewhere (`https:`, `ws:`, …) is a host the server contacts, and any other
/// (`docs://index`, `postgres://…/table`) names what only the server resolves,
/// so only the server's own `read_resource` rules decide it. A host also reads
/// resources for the person, so this reads no more into a URI than it says.
///
/// # Errors
/// For a `file:` URI without an absolute path.
pub fn mcp_resource_action(server: &str, uri: &str) -> Result<Action, HostError> {
    let lower = uri.get(..8).unwrap_or(uri).to_ascii_lowercase();
    let connects = super::unknown::URL_SCHEMES
        .iter()
        .any(|scheme| lower.starts_with(scheme));
    if !connects && !lower.starts_with("file:") {
        return Ok(Action::mcp(format!("mcp__{server}__read_resource")));
    }
    super::mcp::read_resource(
        "resources/read",
        &serde_json::json!({"server": server, "uri": uri}),
    )
}

/// The MCP request for a server's tools, the page after `cursor` when one is
/// given: what `openmoat mcp proxy` sends when a server says its tools changed.
#[must_use]
pub fn mcp_tools_list_request(id: &str, cursor: Option<&str>) -> Value {
    let mut request = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"});
    if let Some(cursor) = cursor {
        request["params"] = serde_json::json!({ "cursor": cursor });
    }
    request
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_keys_at_every_level_and_keeps_values() {
        let text = "\u{2028}\"";
        let value = json!({"b": [{"z": 1, "a": text}], "a": {"y": null, "x": 1.5}});
        let expected = format!(
            r#"{{"a":{{"x":1.5,"y":null}},"b":[{{"a":"{}\"","z":1}}]}}"#,
            '\u{2028}'
        );
        assert_eq!(canonical_json(&value), expected);
        let reordered = json!({"a": {"x": 1.5, "y": null}, "b": [{"a": text, "z": 1}]});
        assert_eq!(canonical_json(&value), canonical_json(&reordered));
    }

    #[test]
    fn absent_and_null_arguments_are_an_empty_object() {
        assert_eq!(mcp_call_arguments(None), "{}");
        assert_eq!(mcp_call_arguments(Some(&Value::Null)), "{}");
        assert_eq!(mcp_call_arguments(Some(&json!({}))), "{}");
    }

    #[test]
    fn a_hook_reads_the_arguments_a_proxy_reads() {
        let action = Action::mcp("mcp__gh__create_issue");
        let object = json!({"title": "t", "body": "b"});
        let sent = mcp_call_arguments(Some(&json!({"body": "b", "title": "t"})));
        assert_eq!(
            hook_arguments(Some(&action), &object).as_deref(),
            Some(sent.as_str())
        );
        // Cursor sends the input as a JSON string.
        let text = Value::String(object.to_string());
        assert_eq!(
            hook_arguments(Some(&action), &text).as_deref(),
            Some(sent.as_str())
        );
        assert_eq!(
            hook_arguments(Some(&Action::mcp("x")), &Value::Null).as_deref(),
            Some("{}")
        );
        let shell = Action::Shell {
            command: "ls".into(),
        };
        assert_eq!(hook_arguments(Some(&shell), &object), None);
        assert_eq!(hook_arguments(None, &object), None);
    }

    #[test]
    fn the_proxy_actions_are_the_hooks() {
        let args = json!({"path": "~/.ssh/id_rsa"});
        assert_eq!(
            mcp_call_action("mcp__fs__read_file", &args).unwrap(),
            super::super::mcp::action("mcp__fs__read_file", &args).unwrap()
        );
        assert_eq!(
            mcp_call_action("mcp__gh__list", &Value::Null).unwrap(),
            Action::mcp("mcp__gh__list")
        );
        let Action::McpTool { name, reads, .. } =
            mcp_resource_action("fs", "file:///etc/passwd").unwrap()
        else {
            panic!("not an MCP action")
        };
        assert_eq!(
            (name.as_str(), reads),
            ("mcp__fs__read_resource", vec!["/etc/passwd".into()])
        );
        assert!(mcp_resource_action("fs", "file:relative").is_err());
        let Action::McpTool { hosts, .. } =
            mcp_resource_action("web", "HTTPS://collector.example.net/x").unwrap()
        else {
            panic!("not an MCP action")
        };
        assert_eq!(hosts, ["HTTPS://collector.example.net/x"]);
        assert_eq!(
            mcp_resource_action("docs", "docs://index").unwrap(),
            Action::mcp("mcp__docs__read_resource"),
            "a scheme only the server resolves names no host"
        );
    }
}
