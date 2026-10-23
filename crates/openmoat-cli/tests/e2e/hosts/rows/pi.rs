//! The row for `pi`.
//!
//! OpenMoat's pi extension: as OpenClaw's plugin; pi runs what OpenMoat
//! makes no decision on, so a secret path must never pass.

use serde_json::json;

use super::{DECISION, Edit, HooksOff, Mcp, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "pi",
        hook: "pi",
        governed: "pi/bash.json",
        unknown_tool: || {
            json!({"hook_event_name": "tool_call", "toolName": "future_tool",
                "input": {"path": "~/.ssh/id_rsa"}, "sessionId": "s", "cwd": "/p"})
        },
        unknown_event: || {
            json!({"hook_event_name": "tool_result", "toolName": "bash",
                "input": {"command": "ls"}})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            crate::pi::payload(sb, "read", &json!({"path": "@~/.ssh/id_ed25519"}))
        }),
        benign: Some(|sb| crate::pi::payload(sb, "bash", &json!({"command": "git status"}))),
        ungoverned: &[|sb| crate::pi::payload(sb, "codemode", &json!({"code": "1"}))],
        malformed: Some((|_| fixture("pi/read-malformed.json"), None)),
        ask: Some(|sb| {
            let outside = json!({"path": sb.home.join("notes/todo.txt")});
            crate::pi::payload(sb, "read", &outside)
        }),
        // Tools spelled as pi spells them: `mcp__<server>__…`, `_` for `-`.
        mcp: Some(Mcp {
            file: "mcp.json",
            servers: |command| {
                json!({ "mcpServers": { "internal-tools": { "command": command } } }).to_string()
            },
            command: "npx",
            server: "internal-tools",
            tool: "mcp__internal_tools__run",
            other_tool: None,
            pinned: "1 definitions pinned",
            call: |sb, tool| crate::pi::payload(sb, tool, &json!({})),
        }),
        // An `extensions` entry that excludes OpenMoat's extension.
        hooks_off: Some(HooksOff {
            file: "settings.json",
            change: |_| r#"{"extensions": ["-extensions/openmoat.js"]}"#.to_owned(),
            before_init: false,
            names: "-extensions/openmoat.js",
        }),
        persons_file: Some("export default function (pi) {}\n"),
        owns_file: true,
        edited: Some(Edit {
            change: |hook| hook.replace("return await answer(", "return; await answer("),
            call: |sb| crate::pi::payload(sb, "bash", &json!({ "command": "git status" })),
        }),
        ..DECISION
    }
}
