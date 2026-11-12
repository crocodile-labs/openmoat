//! GitHub Copilot CLI's `postToolUse` hook: a tool ran, and the payload
//! carries what it returned, read for injected input (ADR-057, ADR-063 step 6).
//!
//! The camelCase payload is the `preToolUse` one (`sessionId`, `timestamp`,
//! `cwd`, `toolName`, `toolArgs`, `toolCallId`) plus `toolResult`
//! (`resultType`, `textResultForLlm`: what the model gets). It names no
//! event, so `toolResult` is what tells it apart: the CLI hooks reference
//! (<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>,
//! "Payload fields") lists it for `postToolUse` only. The weekly latest-agents
//! run 42853181916 (2026-11-10) recorded these fields from a real Copilot CLI
//! on macOS and Linux, with `toolArgs` as an object, which the adapter reads
//! as it reads the string form.
//!
//! Copilot waits for the hook before its next model request (the same run).
//! The hook fires only "after each tool completes successfully"; a failed
//! call fires `postToolUseFailure`, which OpenMoat does not install. Its
//! answer could replace the result (`modifiedResult`) or add to it
//! (`additionalContext`); OpenMoat's is always empty. A non-zero exit, exit 2
//! included, and a timeout are logged and the run goes on.

use serde::Deserialize;
use serde_json::Value;

use crate::{HookEvent, HookRequest, Host, HostError};

/// The event name in Copilot's hook file.
pub(super) const EVENT: &str = "postToolUse";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    #[serde(default)]
    tool_result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult {
    text_result_for_llm: String,
}

/// Whether `payload` is a `postToolUse` one: it carries a `toolResult`. A
/// payload that is not JSON, or whose `toolResult` is `null`, is not, so it
/// is decided as a call (`preToolUse`).
pub(super) fn is_after_call(payload: &str) -> bool {
    serde_json::from_str::<Envelope>(payload).is_ok_and(|e| e.tool_result.is_some())
}

/// The request for a `postToolUse` payload: the call mapped as its
/// `preToolUse` was, with `toolResult.textResultForLlm` as its output. A
/// `toolResult` without that string is malformed.
pub(super) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let mut request = super::parse(host, payload)?;
    let envelope: Envelope = serde_json::from_str(payload)?;
    let missing = || HostError::MissingField {
        tool: EVENT.to_owned(),
        field: "toolResult.textResultForLlm",
    };
    let result: ToolResult =
        serde_json::from_value(envelope.tool_result.ok_or_else(missing)?).map_err(|_| missing())?;
    request.event = HookEvent::PostToolUse {
        output: crate::wire::output::text_of(&Value::String(result.text_result_for_llm)),
    };
    Ok(request)
}
