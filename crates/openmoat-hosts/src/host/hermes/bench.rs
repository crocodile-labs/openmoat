//! `moat bench` for Hermes Agent: the `pre_tool_call` payload of each call,
//! and how Hermes reads the hook's reply (`_evaluate_result` and
//! `_parse_pre_tool_call` in `agent/shell_hooks.py`, v0.22.5).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

pub(super) fn payload(call: &Call, at: &Place<'_>) -> String {
    let (tool, input) = match call {
        Call::Shell(command) => ("terminal".to_owned(), json!({ "command": command })),
        Call::Read(path) => ("read_file".to_owned(), json!({ "path": at.file(path) })),
        Call::Write(path) => (
            "write_file".to_owned(),
            json!({ "path": at.file(path), "content": CONTENT }),
        ),
        Call::Edit(path) => (
            "patch".to_owned(),
            json!({ "path": at.file(path), "old_string": "old", "new_string": CONTENT }),
        ),
        Call::Fetch(url) => ("web_extract".to_owned(), json!({ "urls": [url] })),
        Call::Mcp { server, tool, args } => (format!("mcp__{server}__{tool}"), args.clone()),
    };
    json!({
        "hook_event_name": super::EVENT, "tool_name": tool, "tool_input": input,
        "session_id": at.session, "cwd": at.cwd(), "profile": "default",
        "extra": {
            "task_id": at.session, "tool_call_id": at.call_id, "turn_id": "t-1",
            "api_request_id": "r-1", "middleware_trace": [],
        },
    })
    .to_string()
}

/// Exit 2 blocks whatever stdout says. Otherwise stdout is read: `block` (as
/// `decision` or `action`) blocks, `action: approve` asks the person, any
/// other object is no decision. Under `fail_closed`, which OpenMoat's entry
/// sets, a non-zero exit without a decision, output that is not a JSON
/// object, a signal or a timeout block the call: a failed hook.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    if exit.code == Some(2) {
        return Answer::Deny;
    }
    let Some(code) = exit.code else {
        return Answer::Error;
    };
    let stdout = exit.stdout.trim();
    let document = exit.document();
    let blocks = ["action", "decision"]
        .iter()
        .any(|key| document[*key] == "block");
    if blocks {
        Answer::Deny
    } else if document["action"] == "approve" {
        Answer::Ask
    } else if code == 0 && (stdout.is_empty() || document.is_object()) {
        Answer::Passthrough
    } else {
        Answer::Error
    }
}

/// Hermes has no allow that skips its own checks: OpenMoat's `{}` for an
/// `allow` is no decision there, so an allow arrives as a passthrough.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        other => other.into(),
    }
}
