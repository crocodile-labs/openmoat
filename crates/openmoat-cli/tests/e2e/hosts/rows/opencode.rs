//! The row for `opencode`.
//!
//! OpenMoat's OpenCode plugin: as pi's extension, a file OpenMoat owns whole;
//! OpenCode runs what OpenMoat makes no decision on, so a secret path must
//! never pass. OpenCode 1 has no setting that turns a plugin off, so no
//! `hooks_off`; OpenCode 2 and a moved `XDG_CONFIG_HOME`: `opencode.rs`.

use serde_json::json;

use super::{DECISION, Edit, Mcp, Row};
use crate::common::fixture;

pub fn row() -> Row {
    Row {
        id: "opencode",
        hook: "opencode",
        governed: "opencode/bash.json",
        unknown_tool: || {
            json!({"hook_event_name": "tool.execute.before", "tool": "future_tool",
                "args": {"path": "~/.ssh/id_rsa"}, "sessionID": "s", "directory": "/p"})
        },
        unknown_event: || {
            json!({"hook_event_name": "tool.execute.after", "tool": "bash",
                "args": {"command": "ls"}})
        },
        checks_unknown_tools: true,
        secret_read: Some(|sb| {
            let key = sb.home.join(".ssh/id_ed25519");
            crate::opencode::payload(sb, "read", &json!({"filePath": key}))
        }),
        // A file in the project: OpenCode's shell on Windows is left to it.
        benign: Some(|sb| {
            let file = sb.project().join("src/main.rs");
            crate::opencode::payload(sb, "read", &json!({"filePath": file}))
        }),
        ungoverned: &[|sb| {
            crate::opencode::payload(
                sb,
                "task",
                &json!({"description": "d", "prompt": "p", "subagent_type": "general"}),
            )
        }],
        malformed: Some((|_| fixture("opencode/read-malformed.json"), None)),
        ask: Some(|sb| {
            let outside = json!({"filePath": sb.home.join("notes/todo.txt")});
            crate::opencode::payload(sb, "read", &outside)
        }),
        // Tools spelled as OpenCode spells them: `<server>_<tool>`, `-` kept.
        mcp: Some(Mcp {
            file: "opencode.json",
            servers: |command| {
                json!({ "mcp": { "internal-tools": { "type": "local", "command": [command] } } })
                    .to_string()
            },
            command: "npx",
            server: "internal-tools",
            tool: "internal-tools_run",
            other_tool: None,
            pinned: "1 definitions pinned",
            call: |sb, tool| crate::opencode::payload(sb, tool, &json!({})),
        }),
        persons_file: Some("export default async () => ({})\n"),
        owns_file: true,
        edited: Some(Edit {
            change: |hook| hook.replace("if (error) throw error;", "if (error) return;"),
            call: |sb| crate::opencode::payload(sb, "bash", &json!({ "command": "git status" })),
        }),
        ..DECISION
    }
}
