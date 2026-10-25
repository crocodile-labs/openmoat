//! `moat bench` for OpenCode: what OpenMoat's plugin sends, and how it reads
//! the reply (`host/opencode/integration/openmoat.js`).

use openmoat_core::Verdict;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};

/// OpenCode on the platform the bench runs on, its MCP tools named
/// `<server>_<tool>` with the server among the configured ones the plugin
/// sends. `None` for a shell command on Windows, where OpenCode's shell may be
/// Git Bash, PowerShell or `cmd` and OpenMoat leaves it to OpenCode
/// (`unparseable`): the bench scores the shell it reads.
pub(super) fn payload(call: &Call, at: &Place<'_>) -> Option<String> {
    let mut servers: Vec<String> = Vec::new();
    let (tool, args) = match call {
        Call::Shell(_) if cfg!(windows) => return None,
        Call::Shell(command) => ("bash".to_owned(), json!({ "command": command })),
        Call::Read(path) => ("read".to_owned(), json!({ "filePath": at.file(path) })),
        Call::Write(path) => (
            "write".to_owned(),
            json!({ "filePath": at.file(path), "content": CONTENT }),
        ),
        Call::Edit(path) => (
            "edit".to_owned(),
            json!({ "filePath": at.file(path), "oldString": "old", "newString": CONTENT }),
        ),
        Call::Fetch(url) => (
            "webfetch".to_owned(),
            json!({ "url": url, "format": "markdown" }),
        ),
        Call::Mcp { server, tool, args } => {
            servers.push(server.clone());
            (format!("{server}_{tool}"), args.clone())
        }
    };
    let platform = if cfg!(windows) { "win32" } else { "linux" };
    Some(
        json!({
            "hook_event_name": super::EVENT, "tool": tool, "args": args,
            "sessionID": at.session, "callID": at.call_id,
            "directory": at.cwd(), "worktree": at.cwd(), "mcpServers": servers,
            "platform": platform,
        })
        .to_string(),
    )
}

/// Nothing on exit 0 is no decision, an allow lets the call run, exit 2 with
/// a deny blocks, and anything else blocks too: the plugin has no ask.
pub(super) fn read_reply(exit: &Exit<'_>) -> Answer {
    let document = exit.document();
    match exit.code {
        Some(0) if exit.stdout.trim().is_empty() => Answer::Passthrough,
        Some(0) if document["decision"] == "allow" => Answer::Passthrough,
        Some(2) if document["decision"] == "deny" => Answer::Deny,
        _ => Answer::Error,
    }
}

/// The plugin returns no decision for an `allow`, so OpenCode's own rules
/// still run: an allow is a passthrough there. OpenCode 1 cannot ask, so an
/// `ask` has to arrive as a deny.
pub(super) fn seen(verdict: Verdict) -> Answer {
    match verdict {
        Verdict::Allow => Answer::Passthrough,
        Verdict::Ask => Answer::Deny,
        other => other.into(),
    }
}
