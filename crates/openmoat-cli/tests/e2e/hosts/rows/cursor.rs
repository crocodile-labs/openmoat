//! The row for `cursor`.
//!
//! Uninstall: `uninstall.rs`; an ask: `cursor.rs`.

use serde_json::{Value, json};

use super::{BASE, Row};
use crate::common::{Sandbox, fixture};

pub fn row() -> Row {
    Row {
        id: "cursor",
        hook: "cursor",
        verdict_at: "/permission",
        reason_at: &["/user_message", "/agent_message"],
        governed: "cursor/preToolUse-write.json",
        unknown_tool: || {
            json!({"conversation_id": "s", "hook_event_name": "preToolUse",
                "workspace_roots": ["/p"], "tool_name": "FutureTool",
                "tool_input": {"file_path": "~/.ssh/id_rsa"}})
        },
        unknown_event: || json!({"hook_event_name": "afterFileEdit", "file_path": "/p/x"}),
        checks_unknown_tools: true,
        secret_read: Some(cursor_secret_read),
        benign: Some(|sb| {
            let file = sb.project().join("src/main.rs");
            let input = json!({"file_path": file.to_string_lossy(), "content": ""});
            cursor(sb, "Write", &input)
        }),
        ungoverned: &[|_| fixture("cursor/preToolUse-shell.json")],
        malformed: Some((
            |_| fixture("cursor/beforeMCPExecution-malformed.json"),
            Some("arguments cannot be checked"),
        )),
        ..BASE
    }
}

/// A Cursor `preToolUse` call in the project.
fn cursor(sb: &Sandbox, tool: &str, input: &Value) -> String {
    let project = sb.project();
    json!({
        "conversation_id": "c", "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "tool_name": tool, "tool_input": input, "tool_use_id": "tu-9"
    })
    .to_string()
}

/// Cursor's `beforeReadFile` of a secret.
fn cursor_secret_read(sb: &Sandbox) -> String {
    json!({
        "conversation_id": "conv-42", "generation_id": "gen-9",
        "hook_event_name": "beforeReadFile", "cursor_version": "2.3.1",
        "workspace_roots": [sb.home.to_string_lossy()],
        "file_path": sb.home.join(".aws").join("credentials").to_string_lossy(),
        "content": "[default]", "attachments": []
    })
    .to_string()
}
