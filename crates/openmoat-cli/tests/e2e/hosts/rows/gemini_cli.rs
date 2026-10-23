//! The row for `gemini-cli`.
//!
//! Gemini CLI: an unknown tool is `tool.unknown` too. An allowed call,
//! an ungoverned tool and an ask: `gemini_cli.rs`, which checks the
//! whole reply.

use serde_json::{Value, json};

use super::{DECISION, Edit, HooksOff, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "gemini-cli",
        hook: "gemini-cli",
        governed: "gemini-cli/write_file.json",
        unknown_tool: || {
            json!({"session_id": "s", "cwd": "/p", "hook_event_name": "BeforeTool",
                "tool_name": "future_tool", "tool_input": {"path": "~/.ssh/id_rsa"}})
        },
        unknown_event: || {
            json!({"session_id": "s", "cwd": "/p", "hook_event_name": "AfterTool",
                "tool_name": "read_file", "tool_input": {"file_path": "/p/x"}})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            let input = json!({ "file_path": secret.to_string_lossy() });
            crate::gemini_cli::payload(sb, "read_file", &input)
        }),
        // `init` pins the settings file as it finds it.
        hooks_off: Some(HooksOff {
            file: "settings.json",
            change: |_| json!({ "hooksConfig": { "enabled": false } }).to_string(),
            before_init: true,
            names: "hooksConfig.enabled",
        }),
        malformed: Some((
            |_| fixture("gemini-cli/read_file-malformed.json"),
            Some("file_path"),
        )),
        persons_file: Some(crate::gemini_cli::ORIGINAL),
        edited: Some(Edit {
            change: |hook| {
                let mut root: Value = serde_json::from_str(hook).unwrap();
                root["hooksConfig"] = json!({ "disabled": ["openmoat"] });
                root.to_string()
            },
            call: |sb| {
                let file = sb.project().join("a.txt");
                let input = json!({ "file_path": file.to_string_lossy(), "content": "" });
                crate::gemini_cli::payload(sb, "write_file", &input)
            },
        }),
        ..DECISION
    }
}
