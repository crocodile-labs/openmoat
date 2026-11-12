//! Hook formats more than one host sends, and the argument reading they share.

use openmoat_core::Verdict;

pub(crate) mod guard_command;
pub(crate) mod hook_file;
pub(crate) mod mcp;
pub(crate) mod mcp_call;
pub(crate) mod output;
pub(crate) mod owned_file;
pub(crate) mod plugin_config;
pub(crate) mod pre_tool_use;
pub(crate) mod unknown;

/// The word a host's hook protocol reads for `verdict`. OpenMoat's `review`
/// is sent as the host's `"ask"` (ADR-053): Claude Code, Codex, Copilot CLI,
/// Cursor and Gemini CLI spell it so, and the plugins for OpenClaw, OpenCode
/// and pi, including those an older release installed, read `"ask"` from
/// `openmoat guard`. Every adapter renders the verdict through this function,
/// never through [`Verdict::as_str`], so OpenMoat's own name never reaches a host.
pub(crate) fn host_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Review => "ask",
        other => other.as_str(),
    }
}

/// `value` as canonical JSON: object keys sorted, no whitespace, so two
/// payloads with the same arguments give the same text whatever order the
/// host wrote them in ([`crate::HookRequest::input`]).
pub(crate) fn canonical(value: &serde_json::Value) -> String {
    fn write(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                out.push('{');
                for (n, (key, item)) in entries.into_iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::from(key.as_str()).to_string());
                    out.push(':');
                    write(item, out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (n, item) in items.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use openmoat_core::Verdict;

    #[test]
    fn canonical_json_sorts_keys_and_drops_whitespace() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{ "b": [1, {"y": 2, "x": "\n"}], "a": null }"#).unwrap();
        assert_eq!(
            super::canonical(&a),
            r#"{"a":null,"b":[1,{"x":"\n","y":2}]}"#
        );
    }

    use super::host_verdict;

    #[test]
    fn review_is_the_hosts_ask_and_the_rest_keep_their_names() {
        assert_eq!(host_verdict(Verdict::Review), "ask");
        for (verdict, word) in [
            (Verdict::Allow, "allow"),
            (Verdict::Defer, "defer"),
            (Verdict::Deny, "deny"),
        ] {
            assert_eq!(host_verdict(verdict), word);
        }
    }
}
