//! `moat bench` for GitHub Copilot CLI: the `preToolUse` payload of each call,
//! and how the CLI reads the reply.

use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// The camelCase payload, `toolArgs` as the JSON string the CLI sends; `None`
/// for an MCP call. Copilot's hook payload carries only the model-facing tool
/// name, not the server, so OpenMoat cannot match a server's rules (such as
/// `safe-mcp`) for it: the call is checked by its arguments alone and a
/// scenario's MCP expectations do not apply to this host.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, args) = match call {
        Call::Shell(command) => ("bash".to_owned(), json!({ "command": command })),
        Call::Read(path) => ("view".to_owned(), json!({ "path": at.file(path) })),
        Call::Write(path) => (
            "create".to_owned(),
            json!({ "path": at.file(path), "file_text": CONTENT }),
        ),
        Call::Edit(path) => (
            "edit".to_owned(),
            json!({ "path": at.file(path), "old_str": "old", "new_str": CONTENT }),
        ),
        Call::Fetch(url) => ("web_fetch".to_owned(), json!({ "url": url })),
        Call::Mcp { .. } => return None,
    };
    Some(
        json!({
            "sessionId": at.session, "timestamp": 1_792_540_800_000_u64, "cwd": at.cwd(),
            "toolName": tool, "toolArgs": args.to_string(),
        })
        .to_string(),
    )
}

/// Exit 2 denies whatever stdout says. On exit 0, empty stdout is no decision
/// and `permissionDecision` is read; any other exit is a failed hook, which
/// Copilot answers with a deny for `preToolUse` (`SPEC.on_hook_failure`).
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    match exit.code {
        Some(2) => Answer::Deny,
        Some(0) if exit.stdout.trim().is_empty() => Answer::Passthrough,
        Some(0) => match exit.document()["permissionDecision"].as_str() {
            Some("allow") => Answer::Allow,
            Some("deny") => Answer::Deny,
            Some("ask") => Answer::Ask,
            _ => Answer::Error,
        },
        _ => Answer::Error,
    }
}
