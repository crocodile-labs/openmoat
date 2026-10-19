//! `moat bench` in the `PreToolUse` format: the payload, and how Claude Code
//! and Codex read the reply.

use serde_json::{Value, json};

use crate::bench::{Answer, Call, Exit, Place};

/// The tool and input both hosts send for `call`: `Bash` and MCP tools.
pub(crate) fn common_tool(call: &Call) -> Option<(String, Value)> {
    match call {
        Call::Shell(command) => Some(("Bash".to_owned(), json!({ "command": command }))),
        Call::Mcp { server, tool, args } => Some((format!("mcp__{server}__{tool}"), args.clone())),
        _ => None,
    }
}

/// The `PreToolUse` document for `tool` with `input` at `at`.
pub(crate) fn payload(tool: &str, input: &Value, at: &Place<'_>) -> String {
    json!({
        "session_id": at.session, "turn_id": "t-1", "cwd": at.cwd(),
        "hook_event_name": super::EVENT, "tool_name": tool,
        "tool_input": input, "tool_use_id": at.call_id,
    })
    .to_string()
}

/// `permissionDecision`, or the older top-level `decision`; anything else on
/// exit 0 is no decision. Exit 2 blocks. `can_ask` is false for a host that
/// rejects `ask` as unsupported and runs the call.
pub(crate) fn read_reply(exit: &Exit<'_>, can_ask: bool) -> Answer {
    match exit.code {
        Some(2) => Answer::Deny,
        Some(0) => {
            let document = exit.document();
            let decision = document["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .or_else(|| document["decision"].as_str());
            match decision {
                Some("allow" | "approve") => Answer::Allow,
                Some("deny" | "block") => Answer::Deny,
                Some("ask") if can_ask => Answer::Ask,
                _ => Answer::Passthrough,
            }
        }
        _ => Answer::Error,
    }
}
