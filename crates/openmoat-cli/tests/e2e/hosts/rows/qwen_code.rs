//! The row for `qwen-code`.
//!
//! Qwen Code answers in Claude Code's format and sends every tool, so an
//! unknown one is `tool.unknown`. `init` beside the person's hooks, a review
//! and a defer: `qwen_code.rs`.

use serde_json::{Value, json};

use super::{Edit, HooksOff, PRE_TOOL_USE, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "qwen-code",
        hook: "qwen-code",
        governed: "qwen-code/write_file.json",
        unknown_tool: || {
            json!({"session_id": "s", "cwd": "/p", "hook_event_name": "PreToolUse",
                "tool_name": "future_tool", "tool_input": {"path": "~/.ssh/id_rsa"}})
        },
        unknown_event: || {
            json!({"session_id": "s", "cwd": "/p", "hook_event_name": "PostToolUse",
                "tool_name": "read_file", "tool_input": {"file_path": "/p/a"},
                "tool_response": "a"})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::qwen_code::payload(
                sb,
                "read_file",
                &json!({ "file_path": secret.to_string_lossy() }),
            )
        }),
        benign: Some(|sb| {
            let dir = sb.project().join("src");
            crate::qwen_code::payload(sb, "list_directory", &json!({ "path": dir }))
        }),
        ungoverned: &[|sb| crate::qwen_code::payload(sb, "todo_write", &json!({"todos": []}))],
        malformed: Some((
            |_| fixture("qwen-code/read_file-malformed.json"),
            Some("file_path"),
        )),
        persons_file: Some(crate::qwen_code::ORIGINAL),
        hooks_off: Some(HooksOff {
            file: "settings.json",
            change: |_| json!({ "disableAllHooks": true }).to_string(),
            before_init: true,
            names: "disableAllHooks",
        }),
        edited: Some(Edit {
            change: |hook| {
                let mut root: Value = serde_json::from_str(hook).unwrap();
                root["disableAllHooks"] = json!(true);
                root.to_string()
            },
            call: |sb| {
                let file = sb.project().join("a.txt");
                crate::qwen_code::payload(
                    sb,
                    "write_file",
                    &json!({ "file_path": file.to_string_lossy(), "content": "" }),
                )
            },
        }),
        ..PRE_TOOL_USE
    }
}
