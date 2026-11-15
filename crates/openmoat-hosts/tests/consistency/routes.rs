//! Routes whose payloads [`super::payload`] builds in a function of their own:
//! OpenCode 2 and the Cline CLI.

use openmoat_core::Action;
use serde_json::{Value, json};

use super::Intent;
use super::payloads::{cline, opencode2, opencode2_path};

/// [`super::payload`] for OpenCode 2, which expands a leading `~`, so a path is sent
/// as written.
pub(super) fn opencode2_route(intent: &Intent) -> Result<(Value, Action), &'static str> {
    match intent {
        Intent::Shell(_) if cfg!(windows) => Err("OpenCode's shell on Windows is not read"),
        Intent::Shell(c) => Ok((
            opencode2("shell", &json!({ "command": c })),
            Action::Shell { command: c.clone() },
        )),
        Intent::Read(p) => Ok((
            opencode2("read", &json!({ "path": opencode2_path(p) })),
            Action::FsRead {
                path: opencode2_path(p),
            },
        )),
        Intent::Write(p) => Ok((
            opencode2(
                "edit",
                &json!({ "path": opencode2_path(p), "oldString": "old", "newString": "new" }),
            ),
            Action::FsWrite {
                path: opencode2_path(p),
            },
        )),
        Intent::Fetch(u) => Ok((
            opencode2("webfetch", &json!({ "url": u, "format": "markdown" })),
            Action::Fetch { url: u.clone() },
        )),
    }
}

/// Qwen Code `PreToolUse` (`crates/openmoat-hosts/src/host/qwen_code/fixtures`).
pub(super) fn qwen(tool: &str, input: &Value) -> Value {
    json!({
        "session_id": "qwen-1", "transcript_path": "/t.jsonl", "cwd": super::CWD,
        "hook_event_name": "PreToolUse", "permission_mode": "default",
        "tool_name": tool, "tool_input": input, "tool_use_id": "call_1",
    })
}

/// [`super::payload`] for Qwen Code.
pub(super) fn qwen_route(intent: &Intent) -> Result<(Value, Action), &'static str> {
    match intent {
        // On Windows the shell is taken to be PowerShell, never classified.
        Intent::Shell(_) if cfg!(windows) => Err("Qwen Code's shell on Windows is not read"),
        Intent::Shell(c) => Ok((
            qwen(
                "run_shell_command",
                &json!({ "command": c, "is_background": false }),
            ),
            Action::Shell { command: c.clone() },
        )),
        Intent::Read(p) => Ok((
            qwen("read_file", &json!({ "file_path": p })),
            Action::FsRead { path: p.clone() },
        )),
        Intent::Write(p) => Ok((
            qwen(
                "edit",
                &json!({ "file_path": p, "old_string": "old", "new_string": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        Intent::Fetch(u) => Ok((
            qwen("web_fetch", &json!({ "url": u, "prompt": "summarise" })),
            Action::Fetch { url: u.clone() },
        )),
    }
}

/// Crush `PreToolUse` (`crates/openmoat-hosts/src/host/crush/fixtures`).
pub(super) fn crush(tool: &str, input: &Value) -> Value {
    json!({
        "event": "PreToolUse", "hook_event_name": "PreToolUse", "session_id": "crush-1",
        "cwd": super::CWD, "tool_name": tool, "tool_input": input, "tool_use_id": "call_1",
    })
}

/// [`super::payload`] for Crush.
pub(super) fn crush_route(intent: &Intent) -> Result<(Value, Action), &'static str> {
    match intent {
        // On Windows Crush's shell was not checked, and is never classified.
        Intent::Shell(_) if cfg!(windows) => Err("Crush's shell on Windows is not read"),
        Intent::Shell(c) => Ok((
            crush("bash", &json!({ "command": c, "description": "d" })),
            Action::Shell { command: c.clone() },
        )),
        Intent::Read(p) => Ok((
            crush("view", &json!({ "file_path": p })),
            Action::FsRead { path: p.clone() },
        )),
        Intent::Write(p) => Ok((
            crush(
                "edit",
                &json!({ "file_path": p, "old_string": "old", "new_string": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        Intent::Fetch(u) => Ok((
            crush("fetch", &json!({ "url": u, "format": "text" })),
            Action::Fetch { url: u.clone() },
        )),
    }
}

/// [`super::payload`] for the Cline CLI.
pub(super) fn cline_route(intent: &Intent) -> Result<(Value, Action), &'static str> {
    match intent {
        // On Windows Cline runs `run_commands` in PowerShell, never classified.
        Intent::Shell(_) if cfg!(windows) => Err("Cline's shell on Windows is not read"),
        Intent::Shell(c) => Ok((
            cline("run_commands", &json!({ "commands": [c] })),
            Action::Shell { command: c.clone() },
        )),
        // Cline resolves a relative path in the workspace, which its payload
        // sends (`workspaceRoots`), so a path is sent as the intent names it.
        Intent::Read(p) => Ok((
            cline("read_files", &json!({ "files": [{ "path": p }] })),
            Action::FsRead { path: p.clone() },
        )),
        Intent::Write(p) => Ok((
            cline(
                "editor",
                &json!({ "path": p, "old_text": "old", "new_text": "new" }),
            ),
            Action::FsWrite { path: p.clone() },
        )),
        Intent::Fetch(u) => Ok((
            cline(
                "fetch_web_content",
                &json!({ "requests": [{ "url": u, "prompt": "summarise it" }] }),
            ),
            Action::Fetch { url: u.clone() },
        )),
    }
}
