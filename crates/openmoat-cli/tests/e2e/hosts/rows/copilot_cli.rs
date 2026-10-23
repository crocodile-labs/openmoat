//! The row for `copilot-cli`.
//!
//! Copilot sends every tool; one it does not document is decided as an
//! MCP tool, its arguments checked as an unknown tool's.

use serde_json::{Value, json};

use super::{BASE, Edit, HooksOff, Mcp, Row};
use crate::common::Sandbox;

pub fn row() -> Row {
    Row {
        id: "copilot-cli",
        hook: "copilot-cli",
        verdict_at: "/permissionDecision",
        reason_at: &["/permissionDecisionReason"],
        governed: "copilot-cli/bash.json",
        unknown_tool: || {
            json!({"sessionId": "s", "cwd": "/p", "toolName": "future_tool",
                "toolArgs": json!({"path": "~/.ssh/id_rsa"}).to_string()})
        },
        unknown_event: || {
            json!({"hook_event_name": "postToolUse", "toolName": "bash",
                "toolArgs": json!({"command": "ls"}).to_string()})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let secret = sb.home.join(".aws").join("credentials");
            copilot(sb, "view", &json!({ "path": secret.to_string_lossy() }))
        }),
        benign: Some(|sb| copilot(sb, "bash", &json!({ "command": "cargo test" }))),
        ungoverned: &[|sb| copilot(sb, "report_intent", &json!({ "intent": "x" }))],
        malformed: Some((
            |sb| {
                json!({"sessionId": "cp-1", "cwd": sb.project().to_string_lossy(),
                    "toolName": "bash", "toolArgs": "{\"command\": "})
                .to_string()
            },
            Some("kernel-error"),
        )),
        mcp: Some(Mcp {
            file: "mcp-config.json",
            servers: |gh| {
                json!({ "mcpServers": {
                    "gh": { "type": "local", "command": gh, "tools": ["*"] },
                    "db": { "type": "http", "url": "https://db.example/mcp" },
                }})
                .to_string()
            },
            command: "npx",
            server: "gh",
            tool: "gh-search",
            other_tool: Some("db-query"),
            pinned: "2 definitions pinned",
            call: |sb, tool| copilot(sb, tool, &json!({ "q": "x" })),
        }),
        hooks_off: Some(HooksOff {
            file: "settings.json",
            change: |_| r#"{"disableAllHooks": true}"#.to_owned(),
            before_init: false,
            names: "disableAllHooks",
        }),
        owns_file: true,
        edited: Some(Edit {
            change: |hook| hook.replace("\"timeoutSec\": 600", "\"timeoutSec\": 1"),
            call: |sb| copilot(sb, "bash", &json!({ "command": "ls" })),
        }),
        ..BASE
    }
}

/// A Copilot CLI `preToolUse` call in the project.
fn copilot(sb: &Sandbox, tool: &str, args: &Value) -> String {
    crate::copilot_cli::payload(&sb.project(), tool, args)
}
