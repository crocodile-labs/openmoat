//! `moat bench` for goose: the `PreToolUse` payload of each call, and how
//! goose reads the hook's reply (`classify_output` and `apply_verdict` in
//! `crates/goose/src/hooks/mod.rs`, v1.57.0).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// `None` for a file read and a fetch, which goose has no tool for (it reads
/// through `shell`), and for a shell command on Windows, where goose runs
/// `cmd`, which OpenMoat leaves to goose.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, input) = match call {
        Call::Shell(_) if super::tools::WINDOWS_SHELL => return None,
        Call::Shell(command) => ("shell".to_owned(), json!({ "command": command })),
        Call::Read(_) | Call::Fetch(_) => return None,
        Call::Write(path) => (
            "write".to_owned(),
            json!({ "path": at.file(path), "content": CONTENT }),
        ),
        Call::Edit(path) => (
            "edit".to_owned(),
            json!({ "path": at.file(path), "before": "old", "after": CONTENT }),
        ),
        Call::Mcp { server, tool, args } => (format!("{server}__{tool}"), args.clone()),
    };
    Some(
        json!({
            "event": super::EVENT, "session_id": at.session, "matcher_context": tool,
            "tool_call_id": at.call_id, "tool_name": tool, "tool_input": input,
            "working_dir": at.cwd(),
        })
        .to_string(),
    )
}

/// Exit 2 blocks; so does `{"decision": "block"}` on stdout whatever the exit
/// code. Exit 0 with nothing on stdout, or `{"decision": "allow"}`, lets the
/// call run. Anything else is a failed hook, which `on_failure: block` (set
/// by OpenMoat's entry) turns into a block.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    if exit.code == Some(2) {
        return Answer::Deny;
    }
    let stdout = exit.stdout.trim();
    let document = exit.document();
    if stdout.starts_with('{') && document["decision"] == "block" {
        return Answer::Deny;
    }
    if exit.code == Some(0) && (stdout.is_empty() || document["decision"] == "allow") {
        return Answer::Passthrough;
    }
    Answer::Error
}

/// goose has put its own approval to the person before the hook runs, so an
/// `allow` skips nothing: a passthrough. It cannot ask, so an `ask` must block.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        Verdict::Ask => Answer::Deny,
        other => other.into(),
    }
}
