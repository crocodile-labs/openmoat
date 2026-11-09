//! The row for `antigravity-cli`.
//!
//! Antigravity CLI: its hook file is outside its configuration directory; an
//! unknown tool is `tool.unknown`. A review, `enabled: false`, the MCP pins
//! and `uninstall`: `antigravity_cli.rs`, which checks the whole reply.

use serde_json::{Value, json};

use super::{DECISION, Edit, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "antigravity-cli",
        hook: "antigravity-cli",
        governed: "antigravity-cli/write_to_file.json",
        unknown_tool: || {
            json!({"conversationId": "s", "workspacePaths": ["/p"],
                "toolCall": {"name": "future_tool", "args": {"path": "~/.ssh/id_rsa"}},
                "stepIdx": 0})
        },
        unknown_event: || {
            json!({"conversationId": "s", "workspacePaths": ["/p"],
                "toolCall": {"name": "view_file", "args": {"AbsolutePath": "/p/x"}},
                "stepIdx": 0, "error": ""})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::antigravity_cli::payload(sb, "view_file", &json!({ "AbsolutePath": secret }))
        }),
        benign: Some(|sb| {
            let file = sb.project().join("src");
            crate::antigravity_cli::payload(sb, "list_dir", &json!({ "DirectoryPath": file }))
        }),
        ungoverned: &[|sb| {
            crate::antigravity_cli::payload(sb, "ask_question", &json!({"questions": []}))
        }],
        malformed: Some((
            |_| fixture("antigravity-cli/view_file-malformed.json"),
            Some("AbsolutePath"),
        )),
        persons_file: Some(crate::antigravity_cli::ORIGINAL),
        edited: Some(Edit {
            change: |hook| {
                let mut root: Value = serde_json::from_str(hook).unwrap();
                root["openmoat"]["enabled"] = json!(false);
                root.to_string()
            },
            call: |sb| {
                let file = sb.project().join("a.txt");
                crate::antigravity_cli::payload(
                    sb,
                    "write_to_file",
                    &json!({ "TargetFile": file.to_string_lossy(), "CodeContent": "" }),
                )
            },
        }),
        defer_answers_allow: true,
        ..DECISION
    }
}
