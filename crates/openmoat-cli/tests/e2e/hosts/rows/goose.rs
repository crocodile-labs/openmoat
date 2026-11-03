//! The row for `goose`.
//!
//! goose reads `{"decision": "block" | "allow", "reason"}`; an unknown tool
//! is `tool.unknown`. Its hook file is OpenMoat's plugin's `hooks.json`,
//! outside its configuration directory. The entry's `on_failure: block`, an
//! ask arriving as a block and `uninstall`: `goose.rs`.

use serde_json::{Value, json};

use super::{DECISION, Edit, HooksOff, Mcp, Row};
use crate::common::fixture;

/// The verdict a goose reply means: `block` is a deny, `allow` an allow.
fn read_verdict(reply: &Value) -> &'static str {
    match reply.pointer("/decision").and_then(Value::as_str) {
        Some("block") => "deny",
        Some("allow") => "allow",
        _ => "",
    }
}

pub fn row() -> Row {
    Row {
        id: "goose",
        hook: "goose",
        read_verdict: Some(read_verdict),
        governed: "goose/write.json",
        unknown_tool: || {
            json!({"event": "PreToolUse", "session_id": "s", "tool_name": "future_tool",
                "tool_input": {"path": "~/.ssh/id_rsa"}, "working_dir": "/p"})
        },
        unknown_event: || {
            json!({"event": "PostToolUse", "session_id": "s", "tool_name": "shell",
                "tool_input": {"command": "ls"}, "working_dir": "/p"})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::goose::payload(sb, "tree", &json!({ "path": secret }))
        }),
        benign: Some(|sb| {
            let file = sb.project().join("src");
            crate::goose::payload(sb, "tree", &json!({ "path": file }))
        }),
        ungoverned: &[|sb| crate::goose::payload(sb, "list_functions", &json!({}))],
        malformed: Some((|_| fixture("goose/shell-malformed.json"), Some("command"))),
        mcp: Some(Mcp {
            file: "config.yaml",
            servers: |command| {
                format!(
                    "extensions:\n  internal-tools:\n    enabled: true\n    type: stdio\n    \
                     name: internal-tools\n    cmd: \"{command}\"\n    args: []\n"
                )
            },
            command: "npx",
            server: "internal-tools",
            tool: "internal-tools__run",
            other_tool: None,
            pinned: "1 definitions pinned",
            call: |sb, tool| crate::goose::payload(sb, tool, &json!({})),
        }),
        hooks_off: Some(HooksOff {
            file: "settings.json",
            change: |_| json!({ "disabledPlugins": ["openmoat"] }).to_string(),
            before_init: true,
            names: "disabledPlugins",
        }),
        owns_file: false,
        edited: Some(Edit {
            change: |hook| {
                let mut root: Value = serde_json::from_str(hook).unwrap();
                root["hooks"]["PreToolUse"][0]["hooks"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("on_failure");
                root.to_string()
            },
            call: |sb| {
                let file = sb.project().join("a.txt");
                crate::goose::payload(sb, "write", &json!({ "path": file, "content": "" }))
            },
        }),
        ..DECISION
    }
}
