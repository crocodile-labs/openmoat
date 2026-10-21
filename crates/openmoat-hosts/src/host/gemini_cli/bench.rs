//! `moat bench` for Gemini CLI: the `BeforeTool` payload of each tool, and how
//! Gemini CLI reads the hook's reply (`hookRunner.js`, `hook-utils.js` in
//! `@google/gemini-cli` 0.65.0).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// `None` for a shell command on Windows, where Gemini CLI runs PowerShell,
/// which OpenMoat leaves to Gemini CLI (`unparseable`): the bench scores the
/// shell it reads.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, input, mcp) = match call {
        Call::Shell(_) if super::tools::POWERSHELL => return None,
        Call::Shell(command) => (
            "run_shell_command".to_owned(),
            json!({ "command": command, "description": "bench" }),
            None,
        ),
        Call::Read(path) => (
            "read_file".to_owned(),
            json!({ "file_path": at.file(path) }),
            None,
        ),
        Call::Write(path) => (
            "write_file".to_owned(),
            json!({ "file_path": at.file(path), "content": CONTENT }),
            None,
        ),
        Call::Edit(path) => (
            "replace".to_owned(),
            json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
            None,
        ),
        Call::Fetch(url) => (
            "web_fetch".to_owned(),
            json!({ "prompt": format!("Summarise {url}") }),
            None,
        ),
        Call::Mcp { server, tool, args } => (
            format!("mcp_{server}_{tool}"),
            args.clone(),
            Some(json!({ "server_name": server, "tool_name": tool, "command": "npx" })),
        ),
    };
    let mut payload = json!({
        "session_id": at.session, "transcript_path": "", "cwd": at.cwd(),
        "hook_event_name": super::EVENT, "timestamp": "2026-10-20T00:00:00.000Z",
        "tool_name": tool, "tool_input": input,
    });
    if let Some(mcp) = mcp {
        payload["mcp_context"] = mcp;
    }
    Some(payload.to_string())
}

/// Gemini CLI parses stdout as JSON whatever the exit code: `deny` (or
/// `block`) blocks, `ask` makes it confirm with the person, anything else is
/// no decision. Without a document, any exit code but 0 and 1 blocks when
/// the hook printed something (stdout, else stderr, becomes the reason); a
/// silent hook, a signal or exit 1 is a warning and the call runs.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    let document = exit.document();
    match document["decision"].as_str() {
        Some("deny" | "block") => return Answer::Deny,
        Some("ask") => return Answer::Ask,
        Some(_) => return Answer::Passthrough,
        None => {}
    }
    let printed = !(exit.stdout.trim().is_empty() && exit.stderr.trim().is_empty());
    match exit.code {
        Some(0) if exit.stdout.trim().is_empty() => Answer::Passthrough,
        Some(code) if code != 0 && code != 1 && printed => Answer::Deny,
        _ => Answer::Error,
    }
}

/// An `allow` skips none of Gemini CLI's own confirmations: a passthrough.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        other => other.into(),
    }
}
