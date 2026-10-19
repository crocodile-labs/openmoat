//! `moat bench` for Cursor: the payload of each hook, and how Cursor reads the
//! reply.

use openmoat_core::Verdict;
use serde_json::{Value, json};

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let common = json!({
        "conversation_id": at.session, "generation_id": at.call_id,
        "cursor_version": "2.3.1", "workspace_roots": [at.cwd()],
    });
    let event = match call {
        Call::Shell(command) => json!({
            "hook_event_name": "beforeShellExecution", "command": command,
            "cwd": at.cwd(), "sandbox": false,
        }),
        Call::Read(path) => json!({
            "hook_event_name": "beforeReadFile", "file_path": at.file(path),
            "content": "", "attachments": [],
        }),
        // Cursor's hooks report an edit as `Write` (its third-party hooks reference).
        Call::Write(path) | Call::Edit(path) => json!({
            "hook_event_name": "preToolUse", "cwd": at.cwd(), "tool_name": "Write",
            "tool_input": { "file_path": at.file(path), "content": CONTENT },
            "tool_use_id": at.call_id,
        }),
        // Cursor sends MCP arguments as a JSON string.
        Call::Mcp { server, tool, args } => json!({
            "hook_event_name": "beforeMCPExecution", "tool_name": tool,
            "tool_input": args.to_string(), "mcp_server_name": server,
        }),
        Call::Fetch(_) => return None,
    };
    let mut merged: Value = common;
    merged.as_object_mut()?.extend(event.as_object()?.clone());
    Some(merged.to_string())
}

/// Cursor reads `permission`; it prompts on `ask` for shell and MCP calls only:
/// `preToolUse` accepts `ask` but runs the call, `beforeReadFile` takes only
/// allow or deny. Exit 2 blocks; anything else is a failure.
pub(super) fn read_reply(call: &Call, exit: &Exit<'_>) -> Answer {
    match exit.code {
        Some(0) => match (exit.document()["permission"].as_str(), call) {
            (Some("allow"), _) => Answer::Allow,
            (Some("deny"), _) => Answer::Deny,
            (Some("ask"), Call::Write(_) | Call::Edit(_)) => Answer::Passthrough,
            (Some("ask"), Call::Shell(_) | Call::Mcp { .. }) => Answer::Ask,
            _ => Answer::Error,
        },
        Some(2) => Answer::Deny,
        _ => Answer::Error,
    }
}

/// Cursor's hooks have no "no decision", so a `defer` is Cursor's own prompt,
/// or OpenMoat's ask for file tools (`Host::decided`), where an ask arrives as
/// a deny.
pub(super) fn seen(call: &Call, verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Ask | Verdict::Defer if call.is_file_tool() => Answer::Deny,
        Verdict::Defer => Answer::Ask,
        other => other.into(),
    }
}
