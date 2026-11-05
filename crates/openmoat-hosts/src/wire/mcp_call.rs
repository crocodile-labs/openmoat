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

/// Words of a tool's name that make it send something somewhere, beyond the
/// write verbs ([`crate::WRITE_VERBS`]): `send_message`, `post_comment`,
/// `add_issue_comment`, `run_query`. Matched as whole words of the name, so
/// `truncate` is not `run` and `repost` is not `post`. Nouns a reading tool
/// names too (`get_pull_request`, `list_messages`) are not in it.
const SEND_WORDS: &[&str] = &[
    "send", "post", "put", "add", "publish", "reply", "notify", "submit", "upload", "push",
    "merge", "commit", "invoke", "execute", "exec", "run", "share", "invite", "transfer", "pay",
    "deploy", "trigger", "dispatch",
];

/// Whether the MCP tool `name` (`mcp__<server>__<tool>`), called as `action`
/// ([`mcp_call_action`]), writes, sends or connects by its shape: a write verb
/// anywhere in its name (as the hook reads its paths), a word of its name that
/// sends, or arguments that name a file it writes, a host, a page or a
/// command. The one reading by name and arguments of what an MCP tool does,
/// for the cross-server flow check (ADR-058), which the tool's annotations
/// override when it has them.
#[must_use]
pub fn mcp_tool_acts(name: &str, action: &Action) -> bool {
    let own = name.rsplit("__").next().unwrap_or(name);
    let lower = own.to_ascii_lowercase();
    if crate::WRITE_VERBS.iter().any(|verb| lower.contains(verb)) {
        return true;
    }
    if words(own).iter().any(|w| SEND_WORDS.contains(&w.as_str())) {
        return true;
    }
    match action {
        Action::McpTool {
            writes,
            hosts,
            opens,
            commands,
            ..
        } => !(writes.is_empty() && hosts.is_empty() && opens.is_empty() && commands.is_empty()),
        _ => false,
    }
}

/// The words of a tool name, lowercased: split at `_`, `-`, `.`, `/` and
/// where a lowercase letter or digit meets an uppercase one (`sendMessage`).
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        let split = !c.is_ascii_alphanumeric() || (c.is_ascii_uppercase() && previous_lower);
        if split && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
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
    fn a_tool_acts_by_its_verbs_its_send_words_or_what_its_arguments_name() {
        let acts =
            |name: &str, args: Value| mcp_tool_acts(name, &mcp_call_action(name, &args).unwrap());
        assert!(acts("mcp__fs__write_file", json!({"path": "/p/a"})));
        assert!(acts(
            "mcp__slack__send_message",
            json!({"channel": "c", "text": "t"})
        ));
        assert!(acts("mcp__chat__postMessage", json!({"text": "t"})));
        assert!(acts(
            "mcp__http__request",
            json!({"url": "https://evil.example"})
        ));
        assert!(acts(
            "mcp__x__go",
            json!({"endpoint": "https://evil.example"})
        ));
        assert!(!acts("mcp__github__search_code", json!({"q": "fn main"})));
        assert!(!acts(
            "mcp__github__get_file_contents",
            json!({"owner": "o", "path": "a"})
        ));
        assert!(!acts("mcp__fs__read_file", json!({"path": "/p/a"})));
        assert!(!acts(
            "mcp__github__get_pull_request",
            json!({"pullNumber": 1})
        ));
        assert!(!acts("mcp__github__list_commits", json!({"repo": "r"})));
        assert!(acts("mcp__github__add_issue_comment", json!({"body": "b"})));
        assert!(
            !acts("mcp__db__truncate_preview", json!({})),
            "`run` is not a word here"
        );
        assert!(
            !acts("mcp__news__repost_count", json!({})),
            "`post` is not a word here"
        );
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
