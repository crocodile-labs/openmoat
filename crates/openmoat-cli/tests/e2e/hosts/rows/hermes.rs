//! The row for `hermes`.
//!
//! Hermes Agent spells each verdict its own way (`decision: block`, `action:
//! approve`, `{}`); an unknown tool is `tool.unknown`. Its `config.yaml` has no
//! setting that turns the hook off; the allowlist that a gateway session needs
//! is `hermes.rs`'s, as are YOLO mode and `approvals.mode: off`.

use serde_json::{Value, json};

use super::{Edit, Mcp, Row};
use crate::common::fixture;

/// The verdict a Hermes reply means: `block` (as `decision` or `action`) is a
/// deny, `action: approve` an ask, any other object an allow.
fn read_verdict(reply: &Value) -> &'static str {
    if ["/decision", "/action"]
        .iter()
        .any(|at| reply.pointer(at) == Some(&json!("block")))
    {
        "deny"
    } else if reply.pointer("/action") == Some(&json!("approve")) {
        "ask"
    } else if reply.is_object() {
        "allow"
    } else {
        ""
    }
}

pub fn row() -> Row {
    Row {
        id: "hermes",
        hook: "hermes",
        verdict_at: "",
        read_verdict: Some(read_verdict),
        reason_at: &["/reason"],
        governed: "hermes/write_file.json",
        unknown_tool: || {
            json!({"hook_event_name": "pre_tool_call", "tool_name": "future_tool",
                "tool_input": {"path": "~/.ssh/id_rsa"}, "session_id": "s", "cwd": "/p"})
        },
        unknown_event: || {
            json!({"hook_event_name": "post_tool_call", "tool_name": "terminal",
                "tool_input": {"command": "ls"}, "session_id": "s", "cwd": "/p"})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::hermes::payload(sb, "read_file", &json!({ "path": secret }))
        }),
        benign: Some(|sb| {
            crate::hermes::payload(sb, "terminal", &json!({ "command": "git status" }))
        }),
        ungoverned: &[|sb| crate::hermes::payload(sb, "todo_list", &json!({ "todos": [] }))],
        malformed: Some((|_| fixture("hermes/read_file-malformed.json"), Some("path"))),
        ask: Some(|sb| {
            let outside = sb.home.join("notes").join("todo.txt");
            crate::hermes::payload(sb, "read_file", &json!({ "path": outside }))
        }),
        // The servers are in `config.yaml` beside the hook, which the lock pins
        // without them.
        mcp: Some(Mcp {
            file: "config.yaml",
            servers: |command| {
                format!("mcp_servers:\n  internal-tools:\n    command: \"{command}\"\n")
            },
            command: "npx",
            server: "internal-tools",
            tool: "mcp__internal_tools__run",
            other_tool: None,
            pinned: "1 definitions pinned",
            call: |sb, tool| crate::hermes::payload(sb, tool, &json!({})),
        }),
        persons_file: Some(crate::hermes::ORIGINAL),
        edited: Some(Edit {
            change: |hook| format!("{hook}plugins:\n  enabled: [helper]\n"),
            call: |sb| crate::hermes::payload(sb, "terminal", &json!({ "command": "git status" })),
        }),
        ..super::BASE
    }
}
