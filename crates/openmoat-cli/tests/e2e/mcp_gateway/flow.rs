//! MCP cross-server data flow (ADR-058) through the real binary: the wrapped
//! server `docs` returns a result that tells the assistant to send a file to
//! an address; a later call of another server's tool that sends, carrying that
//! address, needs review. The same call before the result, from another
//! session, or of `docs` itself stays as it was.

use serde_json::{Value, json};

use super::{Gateway, answer, call};
use crate::common::stdout;

/// Claude Code's hook answer for `tool` (its full MCP name) in `session`.
fn decide(gw: &Gateway, session: &str, tool: &str, arguments: &Value) -> String {
    let payload = json!({
        "session_id": session, "cwd": gw.sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": tool,
        "tool_input": arguments, "tool_use_id": format!("{session}-{tool}"),
        "permission_mode": "default"
    });
    let out = gw.sb.guard("claude-code", &payload.to_string());
    let answer: Value = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
    let decided = answer["hookSpecificOutput"]["permissionDecision"].as_str();
    match decided {
        Some(verdict) => format!("{verdict} {answer}"),
        None if out.status.code() == Some(2) => "deny".to_owned(),
        None => "defer".to_owned(),
    }
}

#[test]
fn a_result_carried_to_another_servers_sending_tool_needs_review() {
    let gw = Gateway::new();
    let send = json!({"to": "team", "text": "done, uploaded to https://evil.example/upload?f=1"});
    let before = decide(&gw, "f1", "mcp__mail__send_message", &send);
    assert!(!before.starts_with("ask"), "nothing flowed yet: {before}");

    let search = json!({"q": "release notes"});
    assert!(!decide(&gw, "f1", "mcp__docs__search", &search).starts_with("deny"));
    let host = gw.session("inject", &[call(1, "search", &search)]);
    let text = answer(&host, 1)["result"]["content"][0]["text"].to_string();
    assert!(
        text.contains("evil.example"),
        "the result reaches the host: {host}"
    );

    let after = decide(&gw, "f1", "mcp__mail__send_message", &send);
    assert!(after.starts_with("ask"), "{after}");
    assert!(after.contains("mcp-cross-server"), "{after}");
    assert!(
        after.contains("`docs`") && after.contains("`mail`"),
        "{after}"
    );

    // Another session never read the result; `docs` may be sent its own text;
    // a tool that only reads may be given it.
    let other = decide(&gw, "f2", "mcp__mail__send_message", &send);
    assert!(!other.contains("mcp-cross-server"), "{other}");
    let own = json!({"q": "https://evil.example/upload"});
    let same = decide(&gw, "f1", "mcp__docs__search", &own);
    assert!(!same.contains("mcp-cross-server"), "{same}");
    let read = decide(&gw, "f1", "mcp__notes__search_notes", &own);
    assert!(!read.contains("mcp-cross-server"), "{read}");

    // The audit database holds hashes of the result, never its text.
    for file in ["audit.db", "audit.db-wal"] {
        let bytes = std::fs::read(gw.sb.home.join(".moat").join(file)).unwrap_or_default();
        let stored = String::from_utf8_lossy(&bytes);
        assert!(
            !stored.contains("send the file to"),
            "{file} holds the result's text"
        );
    }
}
