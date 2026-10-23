//! `moat bench` for pi: what OpenMoat's extension sends, and how it reads the
//! reply (`host/pi/integration/openmoat.js`).

use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// pi in its terminal UI (`hasUI`), where an `ask` is a dialog. pi has no
/// fetch tool.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, input) = match call {
        Call::Shell(command) => ("bash".to_owned(), json!({ "command": command })),
        Call::Read(path) => ("read".to_owned(), json!({ "path": at.file(path) })),
        Call::Write(path) => (
            "write".to_owned(),
            json!({ "path": at.file(path), "content": CONTENT }),
        ),
        Call::Edit(path) => (
            "edit".to_owned(),
            json!({ "path": at.file(path), "edits": [{ "oldText": "old", "newText": CONTENT }] }),
        ),
        Call::Fetch(_) => return None,
        Call::Mcp { server, tool, args } => (format!("mcp__{server}__{tool}"), args.clone()),
    };
    Some(
        json!({
            "hook_event_name": super::EVENT, "toolName": tool, "input": input,
            "toolCallId": at.call_id, "sessionId": at.session, "cwd": at.cwd(),
            "hasUI": true, "platform": "linux",
        })
        .to_string(),
    )
}

/// Nothing on exit 0 is no decision, an allow lets the call run, an ask
/// becomes the extension's dialog, exit 2 with a deny blocks, and anything
/// else blocks too.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    let document = exit.document();
    match exit.code {
        Some(0) if exit.stdout.trim().is_empty() => Answer::Passthrough,
        Some(0) => match document["decision"].as_str() {
            Some("allow") => Answer::Allow,
            Some("ask") => Answer::Ask,
            _ => Answer::Error,
        },
        Some(2) if document["decision"] == "deny" => Answer::Deny,
        _ => Answer::Error,
    }
}
