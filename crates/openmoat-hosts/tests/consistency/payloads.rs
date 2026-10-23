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

/// OpenMoat's pi extension (`crates/openmoat-hosts/src/host/pi/fixtures`).
pub(super) fn pi(tool: &str, input: &Value) -> Value {
    json!({
        "hook_event_name": "tool_call", "toolName": tool, "input": input,
        "toolCallId": "call-1", "sessionId": "sess-1", "cwd": CWD,
        "hasUI": true, "platform": "darwin",
    })
}
