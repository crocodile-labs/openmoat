//! The row for `openclaw`.
//!
//! OpenMoat's OpenClaw plugin: an unknown tool is `tool.unknown`,
//! checked for what its arguments name.

use serde_json::json;

use super::{DECISION, Mcp, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "openclaw",
        hook: "openclaw",
        persons_file: Some("{\n  \"gateway\": { \"port\": 18789 }\n}\n"),
        extra_dir: Some("openmoat"),
        governed: "openclaw/exec.json",
        unknown_tool: || {
            json!({"hook_event_name": "before_tool_call", "toolName": "future_tool",
                "params": {"path": "~/.ssh/id_rsa"}, "sessionId": "s", "cwd": "/p"})
        },
        unknown_event: || {
            json!({"hook_event_name": "after_tool_call", "toolName": "exec",
                "params": {"command": "ls"}})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".ssh/id_ed25519");
            crate::openclaw::payload(sb, "read", &json!({"path": secret}))
        }),
        benign: Some(|sb| crate::openclaw::payload(sb, "exec", &json!({"command": "git status"}))),
        ungoverned: &[
            |sb| {
                crate::openclaw::payload(sb, "message", &json!({"action": "reply", "text": "done"}))
            },
            |sb| crate::openclaw::payload(sb, "session_status", &json!({})),
        ],
        malformed: Some((
            |_| fixture("openclaw/read-malformed.json"),
            Some("cannot be checked"),
        )),
        ask: Some(|sb| {
            let outside = sb.home.join("notes/todo.txt");
            crate::openclaw::payload(sb, "read", &json!({"path": outside}))
        }),
        // JSON5 without comments: read, and written back as JSON.
        mcp: Some(Mcp {
            file: "openclaw.json",
            servers: |docs| {
                format!(
                    "{{\n  mcp: {{ servers: {{ docs: {{ command: '{docs}' }}, db: {{ command: 'db' }}, }}, }},\n}}\n"
                )
            },
            command: "docs-server",
            server: "docs",
            tool: "docs__search",
            other_tool: Some("db__query"),
            pinned: "2 definitions pinned",
            call: |sb, tool| crate::openclaw::payload(sb, tool, &json!({})),
        }),
        ..DECISION
    }
}
