//! Gemini CLI's `AfterTool` hook: a tool ran, and the payload carries what it
//! returned, read for injected input (ADR-057, ADR-063 step 5).
//!
//! The payload is the `BeforeTool` one (`session_id`, `transcript_path`, `cwd`,
//! `hook_event_name`, `timestamp`, `tool_name`, `tool_input`, and for an MCP
//! tool `mcp_context`) plus `tool_response`: an object with `llmContent` (what
//! the model gets), `returnDisplay` (what the person sees) and, when the tool
//! failed, `error`. For a shell call the weekly latest-agents run 42853181916
//! (2026-11-10) recorded `llmContent` and `returnDisplay` as strings from a
//! real Gemini CLI; the hooks reference
//! (<https://geminicli.com/docs/hooks/reference/>, `AfterTool`) names the
//! three fields. OpenMoat reads every string in `tool_response` as the output.
//!
//! The reference says an `AfterTool` answer can hide the result
//! (`decision: "deny"`, or exit 2 with stderr as the replacement) or add to it,
//! so Gemini CLI holds the result until the hook is done. OpenMoat answers it
//! with nothing ([`super::Adapter`]'s `render`). Only a failure of the guard
//! exits 2, and then Gemini CLI hands the model OpenMoat's reason in place of
//! the output; any other non-zero exit, and a timeout, is a warning.

use serde::Deserialize;
use serde_json::Value;

use crate::wire::output;
use crate::{HookEvent, HookRequest, Host, HostError};

/// The event name Gemini CLI's payload carries for the hook.
pub(super) const EVENT: &str = "AfterTool";

#[derive(Deserialize)]
struct Payload {
    /// `None` when absent or `null`: a payload without a result is malformed.
    #[serde(default)]
    tool_response: Option<Value>,
}

/// The request for an `AfterTool` payload: the call mapped as its
/// `BeforeTool` was, with its output.
pub(super) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let mut request = super::parse(host, payload)?;
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
