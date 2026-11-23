//! A tool call's arguments, as the host sent them, flattened for the policy's
//! `when:` conditions (ADR-113): every string, number and boolean under the
//! path of keys that leads to it. What cannot be read whole (text that is not
//! JSON, nesting past the depth the MCP scanner reads) marks the arguments
//! cut, so a negated condition holds.

use openmoat_core::Arguments;
use serde_json::Value;

/// Nesting below this is not read, as for the MCP argument scanner.
const MAX_DEPTH: usize = 8;

/// `text`, the JSON arguments of an MCP call (`HookRequest::mcp_arguments`),
/// flattened; no arguments when the call has none.
pub fn of_mcp(text: Option<&str>) -> Arguments {
    let mut out = Arguments::new();
    let Some(text) = text else {
        return out;
    };
    match serde_json::from_str::<Value>(text) {
        Ok(value) => walk(&value, &mut Vec::new(), 0, &mut out),
        Err(_) => out.mark_cut(),
    }
    out
}

fn walk<'a>(value: &'a Value, path: &mut Vec<&'a str>, depth: usize, out: &mut Arguments) {
    if depth > MAX_DEPTH {
        out.mark_cut();
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                path.push(key);
                walk(value, path, depth + 1, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, path, depth + 1, out);
            }
        }
        Value::String(text) => out.push(path, text),
        Value::Number(n) => out.push(path, &n.to_string()),
        Value::Bool(b) => out.push(path, if *b { "true" } else { "false" }),
        Value::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::of_mcp;

    #[test]
    fn strings_are_kept_under_their_key_path_and_bad_json_is_cut() {
        let args = of_mcp(Some(
            r#"{"to":["a@x.example"],"message":{"ccList":"b@y.example"}}"#,
        ));
        assert!(!args.is_cut());
        assert!(!args.is_empty());
        assert!(of_mcp(None).is_empty());
        assert!(of_mcp(Some("not json")).is_cut());
        let deep = format!("{}1{}", "[".repeat(12), "]".repeat(12));
        assert!(of_mcp(Some(&deep)).is_cut());
    }
}
