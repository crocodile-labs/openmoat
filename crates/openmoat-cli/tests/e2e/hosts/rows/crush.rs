//! The row for `crush`.
//!
//! Crush answers in Claude Code's format, cannot prompt (a review is a deny)
//! and sends every tool, so an unknown one is `tool.unknown`. `init` beside
//! the person's hooks, a subagent's review and a defer: `crush.rs`.

use serde_json::{Value, json};

use super::{Edit, PRE_TOOL_USE, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "crush",
        hook: "crush",
        governed: "crush/write.json",
        unknown_tool: || {
            json!({"event": "PreToolUse", "hook_event_name": "PreToolUse",
                "session_id": "s", "cwd": "/p", "tool_name": "future_tool",
                "tool_input": {"path": "~/.ssh/id_rsa"}})
        },
        unknown_event: || {
            json!({"event": "PostToolUse", "hook_event_name": "PostToolUse",
                "session_id": "s", "cwd": "/p", "tool_name": "view",
                "tool_input": {"file_path": "/p/a"}, "tool_response": "a"})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::crush::payload(
                sb,
                "view",
                &json!({ "file_path": secret.to_string_lossy() }),
            )
        }),
        benign: Some(|sb| {
            let dir = sb.project().join("src");
            crate::crush::payload(sb, "ls", &json!({ "path": dir }))
        }),
        ungoverned: &[|sb| crate::crush::payload(sb, "todos", &json!({"todos": []}))],
        malformed: Some((|_| fixture("crush/view-malformed.json"), Some("file_path"))),
        review: Some(|sb| crate::crush::payload(sb, "agent", &json!({"prompt": "look"}))),
        persons_file: Some(crate::crush::ORIGINAL),
        edited: Some(Edit {
            change: |hook| {
                let mut root: Value = serde_json::from_str(hook).unwrap();
                root["hooks"]["PreToolUse"] = json!([]);
                root.to_string()
            },
            call: |sb| {
                let file = sb.project().join("a.txt");
                crate::crush::payload(
                    sb,
                    "write",
                    &json!({ "file_path": file.to_string_lossy(), "content": "" }),
                )
            },
        }),
        ..PRE_TOOL_USE
    }
}
