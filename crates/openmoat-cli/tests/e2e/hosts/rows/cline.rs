//! The row for `cline`.
//!
//! Cline reads `cancel: true` as a deny and any other object, or nothing, as no
//! decision (`{}` for an allow); its hooks cannot ask, so an ask arrives as a
//! deny. The hook file is OpenMoat's script, owned whole; how it answers when
//! run as Cline runs it is `cline.rs`'s. Cline has no setting that turns hooks
//! off besides `--yolo`, a command-line flag.

use serde_json::{Value, json};

use super::{Edit, Mcp, Row};
use crate::common::fixture;

/// The verdict a Cline reply means.
fn read_verdict(reply: &Value) -> &'static str {
    if reply.pointer("/cancel") == Some(&json!(true)) {
        "deny"
    } else if reply.is_object() {
        "allow"
    } else {
        ""
    }
}

pub fn row() -> Row {
    Row {
        id: "cline",
        hook: "cline",
        verdict_at: "",
        read_verdict: Some(read_verdict),
        reason_at: &["/errorMessage"],
        governed: "cline/run_commands.json",
        unknown_tool: || {
            json!({"hookName": "tool_call", "taskId": "s", "workspaceRoots": ["/p"],
                "tool_call": {"id": "c", "name": "future_tool",
                              "input": {"path": "~/.ssh/id_rsa"}}})
        },
        unknown_event: || {
            json!({"hookName": "tool_result", "taskId": "s", "workspaceRoots": ["/p"],
                "tool_result": {"id": "c", "name": "run_commands",
                                "input": {"commands": ["ls"]}}})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            crate::cline::payload(sb, "read_files", &json!({ "files": [{ "path": secret }] }))
        }),
        benign: Some(|sb| {
            crate::cline::payload(sb, "run_commands", &json!({ "commands": ["git status"] }))
        }),
        ungoverned: &[|sb| {
            crate::cline::payload(
                sb,
                "ask_question",
                &json!({ "question": "?", "options": ["a", "b"] }),
            )
        }],
        malformed: Some((|_| fixture("cline/read_files-malformed.json"), Some("path"))),
        ask: Some(|sb| {
            let outside = sb.home.join("notes").join("todo.txt");
            crate::cline::payload(sb, "read_files", &json!({ "files": [outside] }))
        }),
        // `<server>__<tool>`, recorded as `mcp__<server>__<tool>`.
        mcp: Some(Mcp {
            file: "data/settings/cline_mcp_settings.json",
            servers: |command| {
                json!({ "mcpServers": { "internal-tools": { "command": command } } }).to_string()
            },
            command: "npx",
            server: "internal-tools",
            tool: "internal-tools__run",
            other_tool: None,
            pinned: "1 definitions pinned",
            call: |sb, tool| crate::cline::payload(sb, tool, &json!({})),
        }),
        persons_file: Some("#!/bin/sh\necho '{}'\n"),
        owns_file: true,
        edited: Some(Edit {
            change: |hook| hook.replace("guard --host cline", "guard --host cline || true"),
            call: |sb| {
                crate::cline::payload(sb, "run_commands", &json!({ "commands": ["git status"] }))
            },
        }),
        ..super::BASE
    }
}
