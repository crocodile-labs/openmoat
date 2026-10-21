//! `moat bench` for OpenClaw: what OpenMoat's plugin sends, and how it reads
//! the reply (`integrations/openclaw/openmoat.mjs` in the CLI crate).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// The platform is always a POSIX one: on Windows OpenClaw's `exec` runs
/// PowerShell, which OpenMoat leaves to OpenClaw, so the bench scores the shell
/// it reads.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> String {
    let (tool, params) = match call {
        Call::Shell(command) => ("exec".to_owned(), json!({ "command": command })),
        Call::Read(path) => ("read".to_owned(), json!({ "path": at.file(path) })),
        Call::Write(path) => (
            "write".to_owned(),
            json!({ "path": at.file(path), "content": CONTENT }),
        ),
        Call::Edit(path) => (
            "edit".to_owned(),
            json!({ "path": at.file(path), "edits": [{ "oldText": "old", "newText": CONTENT }] }),
        ),
        Call::Fetch(url) => ("web_fetch".to_owned(), json!({ "url": url })),
        Call::Mcp { server, tool, args } => (format!("{server}__{tool}"), args.clone()),
    };
    let state = at.home.join(super::STATE_DIR_NAME);
    let config = state.join(super::CONFIG_FILE);
    json!({
        "hook_event_name": super::EVENT, "toolName": tool, "params": params,
        "toolCallId": at.call_id, "sessionId": at.session, "cwd": at.cwd(),
        "configPath": config.to_string_lossy(), "stateDir": state.to_string_lossy(),
        "platform": "linux",
    })
    .to_string()
}

/// Nothing on exit 0 is no decision, an ask becomes OpenClaw's approval
/// request, exit 2 with a deny blocks, and anything else blocks too.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    let document = exit.document();
    match exit.code {
        Some(0) if exit.stdout.trim().is_empty() => Answer::Passthrough,
        Some(0) => match document["decision"].as_str() {
            Some("allow") => Answer::Passthrough,
            Some("ask") => Answer::Ask,
            _ => Answer::Error,
        },
        Some(2) if document["decision"] == "deny" => Answer::Deny,
        _ => Answer::Error,
    }
}

/// The plugin returns no decision for an `allow`, so OpenClaw's own checks
/// still run: an allow is a passthrough there.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        other => other.into(),
    }
}
