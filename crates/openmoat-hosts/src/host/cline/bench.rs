//! `moat bench` for Cline: the `tool_call` payload of each call, and how
//! Cline reads the hook's reply (`parseHookControl` and
//! `beforeToolResultFromControl` in `hooks/hook-file-hooks.ts`, `cli-v3.0.74`).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// `None` for a shell command on Windows, where Cline runs `run_commands` in
/// PowerShell and OpenMoat leaves it to Cline.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, input) = match call {
        Call::Shell(_) if cfg!(windows) => return None,
        Call::Shell(command) => ("run_commands".to_owned(), json!({ "commands": [command] })),
        Call::Read(path) => (
            "read_files".to_owned(),
            json!({ "files": [{ "path": at.file(path) }] }),
        ),
        Call::Write(path) => (
            "editor".to_owned(),
            json!({ "path": at.file(path), "new_text": CONTENT }),
        ),
        Call::Edit(path) => (
            "editor".to_owned(),
            json!({ "path": at.file(path), "old_text": "old", "new_text": CONTENT }),
        ),
        Call::Fetch(url) => (
            "fetch_web_content".to_owned(),
            json!({ "requests": [{ "url": url, "prompt": "summarise it" }] }),
        ),
        Call::Mcp { server, tool, args } => (format!("{server}__{tool}"), args.clone()),
    };
    let payload = json!({
        "hookName": super::EVENT, "clineVersion": "", "timestamp": "2026-11-03T10:00:00.000Z",
        "taskId": at.session, "sessionContext": { "rootSessionId": at.session },
        "workspaceRoots": [at.cwd()], "userId": "me", "agent_id": "agent-1",
        "parent_agent_id": null, "iteration": 1,
        "tool_call": { "id": at.call_id, "name": tool, "input": input },
    });
    Some(payload.to_string())
}

/// Cline reads stdout only: `cancel: true` stops the call; any other object,
/// or nothing, is no decision; anything else is a failed hook, and Cline runs
/// the call.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    if exit.stdout.trim().is_empty() {
        return Answer::Passthrough;
    }
    let document = exit.document();
    if document["cancel"] == true {
        Answer::Deny
    } else if document.is_object() {
        Answer::Passthrough
    } else {
        Answer::Error
    }
}

/// Cline has no allow that skips its own approval, and cannot prompt: an allow
/// arrives as a passthrough, a review as a deny.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        Verdict::Review => Answer::Deny,
        other => other.into(),
    }
}
