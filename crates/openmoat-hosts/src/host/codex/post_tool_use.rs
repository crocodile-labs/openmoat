//! Codex's `PostToolUse` hook: a tool ran, and the payload carries what it
//! returned, read for injected input (ADR-057, ADR-063 step 4).
//!
//! The payload is the `PreToolUse` one (`session_id`, `turn_id`, `cwd`,
//! `tool_name`, `tool_input`, `tool_use_id`, `transcript_path`, `model`,
//! `permission_mode`) plus `tool_response`. For a shell call that is a string,
//! as the weekly latest-agents run 42853181916 (2026-11-10) recorded from a
//! real Codex on macOS and Linux; Codex's hooks page types it as any JSON
//! value ("MCP tools send the MCP call result"). OpenMoat reads every string
//! in it as the output.
//!
//! Codex waits for the hook before its next model request (the same run, and
//! <https://learn.chatgpt.com/docs/hooks>: "Codex waits for a command hook").
//! The hook's answer is always empty: a `decision: "block"` or an exit 2 with
//! stderr would replace the call's result with the reason, which nothing here
//! is meant to do. Only a failure of the guard exits 2 ([`super::render`]),
//! and then Codex hands the model OpenMoat's reason in place of the output.

use serde::Deserialize;
use serde_json::Value;

use crate::wire::{output, pre_tool_use};
use crate::{HookEvent, HookRequest, Host, HostError};

/// The event name Codex's payload carries for the hook.
pub(super) const EVENT: &str = "PostToolUse";

#[derive(Deserialize)]
struct Payload {
    /// `None` when absent or `null`: a payload without a result is malformed.
    #[serde(default)]
    tool_response: Option<Value>,
}

/// The request for a `PostToolUse` payload: the call mapped as its
/// `PreToolUse` was, with its output.
pub(super) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let mut request = pre_tool_use::parse_with(host, payload, super::tools::own)?;
    request.action = request.action.map(super::tools::held);
    let p: Payload = serde_json::from_str(payload)?;
    let response = p.tool_response.ok_or(HostError::MissingField {
        tool: EVENT.to_owned(),
        field: "tool_response",
    })?;
    request.event = HookEvent::PostToolUse {
        output: output::text_of(&response),
    };
    Ok(request)
}
