//! The payload each host sends for one tool call, and how each host reads the
//! hook's reply. Payload shapes follow the golden payloads in
//! `tests/fixtures/hosts/`; reply rules follow `docs/ARCHITECTURE.md` §5 and
//! `docs/THREAT_MODEL.md` §5.

use std::path::Path;

use openmoat_core::Verdict;
use openmoat_hosts::Host;
use serde::Serialize;
use serde_json::{Value, json};

use super::Call;
use super::hook::Reply;

/// What the host does with the hook's reply, ordered by strictness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    /// The hook allowed the call.
    Allow,
    /// The hook made no decision the host acts on; the host's own permission
    /// settings apply.
    Passthrough,
    /// The hook failed (crashed, timed out, could not start, or answered outside the
    /// protocol); what the host then does is its failure behaviour ([`failure`]).
    Error,
    /// The host asks the person.
    Ask,
    /// The host blocks the call.
    Deny,
}

impl From<Verdict> for Answer {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            // ADR-025: no decision, the host's own permission flow runs.
            Verdict::Defer => Self::Passthrough,
            Verdict::Ask => Self::Ask,
            // `Deny`, and any verdict added to the core later: the strictest.
            _ => Self::Deny,
        }
    }
}

impl Answer {
    /// The answer as the report spells it.
    pub fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Passthrough => "passthrough",
            Self::Error => "error",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }

    /// Whether this answer satisfies `want`: a hook that leaves an allowed call
    /// to the host's own settings has not blocked it.
    pub fn meets(self, want: Self) -> bool {
        self == want || (want == Self::Allow && self == Self::Passthrough)
    }
}

/// The answer a host must end up with for `verdict` on `call`: Codex cannot ask,
/// nor can Cursor's `beforeReadFile` and `preToolUse` (file reads and writes), so
/// there an `ask` has to arrive as a blocking `deny`. Cursor's hooks have no "no
/// decision", so a `defer` is Cursor's own prompt, or OpenMoat's ask for file tools.
/// OpenMoat's OpenClaw plugin returns no decision for an `allow`, so OpenClaw's own
/// checks still run: an allow is a passthrough there.
pub fn seen(host: Host, call: &Call, verdict: Verdict) -> Answer {
    let file_tool = matches!(call, Call::Read(_) | Call::Write(_) | Call::Edit(_));
    match (host, verdict) {
        (Host::Codex, Verdict::Ask) => Answer::Deny,
        (Host::OpenClaw, Verdict::Allow) => Answer::Passthrough,
        // a `defer` there is OpenMoat's ask (`Host::decided`), and the ask arrives as a deny
        (Host::Cursor, Verdict::Ask | Verdict::Defer) if file_tool => Answer::Deny,
        (Host::Cursor, Verdict::Defer) => Answer::Ask,
        (_, other) => other.into(),
    }
}

/// Read the hook's reply the way `host` does.
pub fn classify(host: Host, call: &Call, reply: &Reply) -> Answer {
    let Reply::Exited {
        code,
        stdout,
        stderr,
    } = reply
    else {
        return Answer::Error;
    };
    let document: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    match (host, *code) {
        // Cursor reads `permission`; it prompts on `ask` for shell and MCP calls only:
        // `preToolUse` accepts `ask` but runs the call, `beforeReadFile` takes only
        // allow or deny.
        (Host::Cursor, Some(0)) => match (document["permission"].as_str(), call) {
            (Some("allow"), _) => Answer::Allow,
            (Some("deny"), _) => Answer::Deny,
            (Some("ask"), Call::Write(_) | Call::Edit(_)) => Answer::Passthrough,
            (Some("ask"), Call::Shell(_) | Call::Mcp { .. }) => Answer::Ask,
            _ => Answer::Error,
        },
        // OpenMoat's OpenClaw plugin: nothing on exit 0 is no decision, an ask
        // becomes OpenClaw's approval request, exit 2 with a deny blocks, and
        // anything else blocks too (`integrations/openclaw/openmoat.mjs`).
        (Host::OpenClaw, Some(0)) if stdout.trim().is_empty() => Answer::Passthrough,
        (Host::OpenClaw, Some(0)) => match document["decision"].as_str() {
            Some("allow") => Answer::Passthrough,
            Some("ask") => Answer::Ask,
            _ => Answer::Error,
        },
        (Host::OpenClaw, Some(2)) if document["decision"] == "deny" => Answer::Deny,
        (Host::OpenClaw, _) => Answer::Error,
        // Codex blocks on exit 2 only with a reason on stderr.
        (Host::Codex, Some(2)) if stderr.trim().is_empty() => Answer::Error,
        (_, Some(2)) => Answer::Deny,
        (Host::Cursor, _) => Answer::Error,
        // Claude Code and Codex `PreToolUse`: `permissionDecision`, or the older
        // top-level `decision`; anything else on exit 0 is no decision. Codex rejects
        // `ask` as unsupported and runs the call.
        (_, Some(0)) => {
            let decision = document["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .or_else(|| document["decision"].as_str());
            match decision {
                Some("allow" | "approve") => Answer::Allow,
                Some("deny" | "block") => Answer::Deny,
                Some("ask") if host != Host::Codex => Answer::Ask,
                _ => Answer::Passthrough,
            }
        }
        _ => Answer::Error,
    }
}

/// What `host` does when its hook is missing, crashes or times out. Host
/// behaviour as documented in `docs/THREAT_MODEL.md` §5 ("When the hook fails")
/// and `docs/ARCHITECTURE.md` §5; change them together.
pub fn failure(host: Host) -> &'static str {
    match host {
        Host::Codex => {
            "runs the call when the hook is missing, cannot start, exits non-zero other \
             than 2 (or 2 with nothing on stderr), or times out (default 600 s)"
        }
        Host::Cursor => {
            "runs the call when the hook is missing, crashes or times out, unless the hook \
             entry sets `failClosed: true`; then it blocks the call"
        }
        Host::OpenClaw => {
            "blocks the call when OpenMoat's plugin throws or times out (OpenClaw's \
             `before_tool_call` fails closed), and the plugin blocks when `moat` is missing, \
             crashes or does not answer; runs the call unchecked when the Gateway does not \
             load the plugin"
        }
        Host::ClaudeCode | Host::Continue => {
            "runs the call when the hook is missing, cannot start, exits non-zero other \
             than 2, or times out (default 600 s)"
        }
    }
}

/// The hook payload for `call`, or `None` when this host has no tool for it
/// (Codex reads files through its shell; only Claude Code has `WebFetch`).
pub fn payload(host: Host, call: &Call, at: &Place<'_>) -> Option<String> {
    let (tool, input) = match (host, call) {
        (Host::Cursor, _) => return cursor(call, at).map(|v| v.to_string()),
        (Host::OpenClaw, _) => return Some(openclaw(call, at).to_string()),
        (_, Call::Shell(command)) => ("Bash".to_owned(), json!({ "command": command })),
        (Host::ClaudeCode, Call::Read(path)) => {
            ("Read".to_owned(), json!({ "file_path": at.file(path) }))
        }
        (Host::ClaudeCode, Call::Write(path)) => (
            "Write".to_owned(),
            json!({ "file_path": at.file(path), "content": CONTENT }),
        ),
        (Host::Codex, Call::Write(path)) => (
            "apply_patch".to_owned(),
            json!({ "command": format!(
                "*** Begin Patch\n*** Add File: {}\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            ) }),
        ),
        (Host::ClaudeCode, Call::Edit(path)) => (
            "Edit".to_owned(),
            json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
        ),
        (Host::Codex, Call::Edit(path)) => (
            "apply_patch".to_owned(),
            json!({ "command": format!(
                "*** Begin Patch\n*** Update File: {}\n@@\n-old\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            ) }),
        ),
        (Host::ClaudeCode, Call::Fetch(url)) => (
            "WebFetch".to_owned(),
            json!({ "url": url, "prompt": "summarise" }),
        ),
        (Host::ClaudeCode | Host::Codex, Call::Mcp { server, tool, args }) => {
            (format!("mcp__{server}__{tool}"), args.clone())
        }
        _ => return None,
    };
    Some(
        json!({
            "session_id": at.session, "turn_id": "t-1", "cwd": at.cwd(),
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": input, "tool_use_id": at.call_id,
        })
        .to_string(),
    )
}

const CONTENT: &str = "written by the agent";

/// Where a call happens: the throwaway home, the project, and its ids.
pub struct Place<'a> {
    pub home: &'a Path,
    pub project: &'a Path,
    pub session: &'a str,
    pub call_id: &'a str,
}

impl Place<'_> {
    fn cwd(&self) -> String {
        self.project.to_string_lossy().into_owned()
    }

    /// File tools send absolute paths: `~/x` is in the home, anything relative
    /// is in the project.
    fn file(&self, path: &str) -> String {
        let full = match path.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None => self.project.join(path),
        };
        full.to_string_lossy().into_owned()
    }
}

/// What OpenMoat's OpenClaw plugin sends (`openmoat-hosts` `openclaw.rs`). The
/// platform is always a POSIX one: on Windows OpenClaw's `exec` runs PowerShell,
/// which OpenMoat leaves to OpenClaw, so the bench scores the shell it reads.
fn openclaw(call: &Call, at: &Place<'_>) -> Value {
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
    let config = at.home.join(".openclaw").join("openclaw.json");
    json!({
        "hook_event_name": "before_tool_call", "toolName": tool, "params": params,
        "toolCallId": at.call_id, "sessionId": at.session, "cwd": at.cwd(),
        "configPath": config.to_string_lossy(), "platform": "linux",
    })
}

fn cursor(call: &Call, at: &Place<'_>) -> Option<Value> {
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
    let mut merged = common;
    merged.as_object_mut()?.extend(event.as_object()?.clone());
    Some(merged)
}
