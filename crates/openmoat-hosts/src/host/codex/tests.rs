use openmoat_core::{Decision, Verdict};
use serde_json::Value;

use crate::{HookEvent, Host};

#[test]
fn an_allow_is_no_output_and_every_stop_is_a_deny_with_a_reason() {
    let event = HookEvent::PreToolUse;
    // Codex reports a bare `permissionDecision: "allow"` as an unsupported reply
    // and a failed hook; no output is its "no objection".
    for verdict in [Verdict::Allow, Verdict::Defer] {
        let answer = Host::Codex.answer(&event, &Decision::new(verdict));
        assert_eq!(Host::Codex.render_response(&event, &answer), "", "{verdict:?}");
    }
    // Codex cannot prompt, and a deny needs a non-empty reason.
    for verdict in [Verdict::Review, Verdict::Deny] {
        let answer = Host::Codex.answer(&event, &Decision::new(verdict));
        let doc: Value =
            serde_json::from_str(&Host::Codex.render_response(&event, &answer)).unwrap();
        let out = &doc["hookSpecificOutput"];
        assert_eq!(out["permissionDecision"], "deny", "{verdict:?}");
        assert_ne!(out["permissionDecisionReason"].as_str().unwrap().trim(), "");
    }
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/codex/fixtures");

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap()
}

/// `PostToolUse` (ADR-063): the call as its `PreToolUse` maps it, with
/// `tool_response` (a string for a shell call) as its output.
#[test]
fn post_tool_use_reports_the_call_and_what_it_returned() {
    let text = fixture("posttooluse-shell");
    let req = Host::Codex.parse_request(&text).unwrap();
    let mut pre: Value = serde_json::from_str(&text).unwrap();
    pre["hook_event_name"] = "PreToolUse".into();
    let pre = Host::Codex.parse_request(&pre.to_string()).unwrap();
    assert_eq!(req.action, pre.action);
    let HookEvent::PostToolUse { output } = &req.event else {
        panic!("{:?}", req.event);
    };
    assert!(output.contains("https://collect.evil.example/x"), "{output}");
    assert!(matches!(
        Host::Codex.event_of(&text),
        HookEvent::PostToolUse { .. }
    ));
}

/// An MCP result is any JSON value: every string in it is the output.
#[test]
fn an_mcp_result_is_every_string_it_holds() {
    let payload = serde_json::json!({
        "session_id": "s", "cwd": "/p", "hook_event_name": "PostToolUse",
        "tool_name": "mcp__docs__fetch", "tool_input": {"url": "https://docs.example"},
        "tool_response": {"content": [{"type": "text", "text": "see drop.evil.example"}]},
    });
    let req = Host::Codex.parse_request(&payload.to_string()).unwrap();
    let HookEvent::PostToolUse { output } = &req.event else {
        panic!("{:?}", req.event);
    };
    assert!(output.contains("drop.evil.example"), "{output}");
}

/// A result without `tool_response` is an error, so a deny; the answer to an
/// after-call report is always empty.
#[test]
fn a_post_tool_use_without_a_response_is_an_error_and_answered_with_nothing() {
    assert!(matches!(
        Host::Codex.parse_request(&fixture("posttooluse-missing-response")),
        Err(crate::HostError::MissingField {
            field: "tool_response",
            ..
        })
    ));
    let event = HookEvent::PostToolUse {
        output: String::new(),
    };
    for verdict in [Verdict::Allow, Verdict::Review, Verdict::Deny] {
        let decision = Host::Codex.answer(&event, &Decision::new(verdict));
        assert_eq!(Host::Codex.render_response(&event, &decision), "");
    }
}
