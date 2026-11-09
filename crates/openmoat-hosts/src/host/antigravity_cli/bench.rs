//! `moat bench` for Antigravity CLI: the `PreToolUse` payload of each tool,
//! and how it reads the hook's reply, as documented
//! (<https://antigravity.google/docs/hooks?tab=cli>).

use openmoat_core::Verdict;
use serde_json::{Value, json};

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// `None` for a shell command on Windows, whose shell OpenMoat does not parse.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let (name, args): (&str, Value) = match call {
        Call::Shell(_) if super::tools::WINDOWS => return None,
        Call::Shell(command) => ("run_command", json!({ "CommandLine": command })),
        Call::Read(path) => ("view_file", json!({ "AbsolutePath": at.file(path) })),
        Call::Write(path) => (
            "write_to_file",
            json!({ "TargetFile": at.file(path), "CodeContent": CONTENT }),
        ),
        Call::Edit(path) => (
            "replace_file_content",
            json!({ "TargetFile": at.file(path), "TargetContent": "old",
                "ReplacementContent": CONTENT }),
        ),
        Call::Fetch(url) => ("read_url_content", json!({ "Url": url })),
        Call::Mcp { server, tool, args } => (
            "call_mcp_tool",
            json!({ "ServerName": server, "ToolName": tool, "Arguments": args }),
        ),
    };
    Some(
        json!({
            "conversationId": at.session, "workspacePaths": [at.cwd()],
            "transcriptPath": "", "artifactDirectoryPath": "", "modelName": "bench",
            "lastUserInput": "", "toolCall": { "name": name, "args": args }, "stepIdx": 0,
        })
        .to_string(),
    )
}

/// `decision`, the one documented field. A hook that exits non-zero or prints
/// no JSON is `Error`: what the host does with one is not documented.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    match exit.document()["decision"].as_str() {
        Some("deny" | "deny_unless_prior_grant") => Answer::Deny,
        Some("ask" | "force_ask") => Answer::Review,
        Some("allow" | "auto_approve") => Answer::Passthrough,
        _ => Answer::Error,
    }
}

/// An `allow` or `defer` is passed on to Antigravity CLI's own policy.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow | Verdict::Defer => Answer::Passthrough,
        other => other.into(),
    }
}
