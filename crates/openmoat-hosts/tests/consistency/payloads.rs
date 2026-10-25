//! The payload each host sends for one tool call, in the shapes of
//! `crates/openmoat-hosts/src/host/<module>/fixtures/`, for the consistency suite.

use serde_json::{Value, json};

use super::{CWD, HOME};

/// Gemini CLI `BeforeTool` (`crates/openmoat-hosts/src/host/gemini_cli/fixtures`).
pub(super) fn gemini(tool: &str, input: &Value) -> Value {
    json!({
        "session_id": "gemini-1", "transcript_path": "", "cwd": CWD,
        "hook_event_name": "BeforeTool", "timestamp": "2026-10-20T00:00:00.000Z",
        "tool_name": tool, "tool_input": input,
    })
}

/// Cursor's common fields with one event's (`crates/openmoat-hosts/src/host/cursor/fixtures`).
pub(super) fn cursor(event: &Value) -> Value {
    let mut payload = json!({
        "conversation_id": "conv-1", "generation_id": "gen-1",
        "cursor_version": "2.3.1", "workspace_roots": [CWD],
    });
    let (Some(common), Some(own)) = (payload.as_object_mut(), event.as_object()) else {
        unreachable!("both are JSON objects");
    };
    common.extend(own.clone());
    payload
}

pub(super) fn cursor_tool(tool: &str, input: &Value) -> Value {
    cursor(&json!({
        "hook_event_name": "preToolUse", "cwd": CWD, "tool_name": tool,
        "tool_input": input, "tool_use_id": "tu-1",
    }))
}

/// OpenMoat's OpenClaw plugin (`crates/openmoat-hosts/src/host/openclaw/fixtures`).
pub(super) fn openclaw(tool: &str, params: &Value) -> Value {
    json!({
        "hook_event_name": "before_tool_call", "toolName": tool, "params": params,
        "toolCallId": "call-1", "runId": "run-1", "sessionId": "sess-1",
        "sessionKey": "agent:main:main", "agentId": "main", "cwd": CWD,
        "configPath": format!("{HOME}/.openclaw/openclaw.json"), "platform": "darwin",
    })
}

/// GitHub Copilot CLI's camelCase `preToolUse`, `toolArgs` as a JSON string
/// (`crates/openmoat-hosts/src/host/copilot_cli/fixtures`).
pub(super) fn copilot(tool: &str, args: &Value) -> Value {
    json!({
        "sessionId": "sess-1", "timestamp": 1_792_540_800_000_u64, "cwd": CWD,
        "toolName": tool, "toolArgs": args.to_string(),
    })
}

/// Hermes Agent `pre_tool_call` (`crates/openmoat-hosts/src/host/hermes/fixtures`).
pub(super) fn hermes(tool: &str, input: &Value) -> Value {
    json!({
        "hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": input,
        "session_id": "hermes-1", "cwd": CWD, "profile": "default",
        "extra": { "task_id": "hermes-1", "tool_call_id": "call-1", "turn_id": "t-1" },
    })
}

/// `path` with a relative one placed in the working directory.
pub(super) fn under_cwd(path: &str) -> String {
    if path.starts_with(['/', '~']) {
        path.to_owned()
    } else {
        format!("{CWD}/{path}")
    }
}

/// OpenMoat's pi extension (`crates/openmoat-hosts/src/host/pi/fixtures`).
pub(super) fn pi(tool: &str, input: &Value) -> Value {
    json!({
        "hook_event_name": "tool_call", "toolName": tool, "input": input,
        "toolCallId": "call-1", "sessionId": "sess-1", "cwd": CWD,
        "hasUI": true, "platform": "darwin",
    })
}

/// OpenMoat's OpenCode plugin (`crates/openmoat-hosts/src/host/opencode/fixtures`).
pub(super) fn opencode(tool: &str, args: &Value) -> Value {
    json!({
        "hook_event_name": "tool.execute.before", "tool": tool, "args": args,
        "sessionID": "ses_1", "callID": "call-1", "directory": CWD, "worktree": CWD,
        "mcpServers": [], "platform": "darwin",
    })
}

/// A file path as OpenCode's model sends it: OpenCode expands no `~`, so a
/// path in the home is written out, and a relative one is joined to the
/// directory, as OpenCode's tools join it.
pub(super) fn opencode_path(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => format!("{HOME}/{rest}"),
        None if path.starts_with('/') => path.to_owned(),
        None => format!("{CWD}/{path}"),
    }
}
