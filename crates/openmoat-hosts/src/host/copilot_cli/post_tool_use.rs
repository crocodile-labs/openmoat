//! GitHub Copilot CLI's `postToolUse` hook: a tool ran, and the payload
//! carries what it returned, read for injected input (ADR-057, ADR-063 step 6).
//!
//! The camelCase payload is the `preToolUse` one (`sessionId`, `timestamp`,
//! `cwd`, `toolName`, `toolArgs`, `toolCallId`) plus `toolResult`
//! (`resultType`, `textResultForLlm`: what the model gets), as the CLI hooks
//! reference
//! (<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>,
//! "Payload fields") lists it. The weekly latest-agents run 42853181916
//! (2026-11-10) recorded these fields from a real Copilot CLI on macOS and
//! Linux, with `toolArgs` as an object, which the adapter reads as it reads
//! the string form.
//!
//! The payload names no event, so the payload never says which one it is:
//! OpenMoat's `postToolUse` entry runs `guard --event postToolUse`
//! ([`crate::HookSpec::names_event`]), and only that entry's payloads are read
//! here. A `toolResult` in any other payload changes nothing.
//!
//! Copilot waits for the hook before its next model request (the same run).
//! The hook fires only "after each tool completes successfully"; a failed
//! call fires `postToolUseFailure`, which OpenMoat does not install. Its
//! answer could replace the result (`modifiedResult`) or add to it
//! (`additionalContext`); OpenMoat's is always empty. A non-zero exit, exit 2
//! included, and a timeout are logged and the run goes on.

use openmoat_core::Action;
use serde::Deserialize;
use serde_json::Value;

use crate::{HookEvent, HookRequest, Host, HostError};

/// The event name in Copilot's hook file and on its entry's command line.
pub(super) const EVENT: &str = "postToolUse";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    #[serde(default)]
    tool_result: Option<Value>,
}

/// `toolResult` as the reference and the run show it: both fields strings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult {
    #[expect(dead_code, reason = "required, so a result without it is refused")]
    result_type: String,
    text_result_for_llm: String,
}

/// The request for a `postToolUse` payload: the call mapped as its
/// `preToolUse` was, with `toolResult.textResultForLlm` as its output. A
/// payload without a `toolResult` holding both strings is malformed.
///
/// Every tool runs this hook (Copilot's payload does not mark MCP tools, so
/// the entry has no matcher). A call whose action can never be untrusted
/// output (a file read or edit, a search over files) keeps no action, so the
/// guard answers it before any other work.
pub(super) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let mut request = super::parse(host, payload)?;
    let p: Payload = serde_json::from_str(payload)?;
    let missing = || HostError::MissingField {
        tool: EVENT.to_owned(),
        field: "toolResult",
    };
    let result: ToolResult =
        serde_json::from_value(p.tool_result.ok_or_else(missing)?).map_err(|_| missing())?;
    request.action = request.action.filter(may_be_untrusted_output);
    request.event = HookEvent::PostToolUse {
        output: crate::wire::output::text_of(&Value::String(result.text_result_for_llm)),
    };
    Ok(request)
}

/// Whether what `action` returned can be content from outside: a command
/// (it may fetch), a fetch, a search, an MCP tool or a tool OpenMoat does not
/// know (`CompiledPolicy::output_source` decides which of these it is).
fn may_be_untrusted_output(action: &Action) -> bool {
    matches!(
        action.shown(),
        Action::Shell { .. }
            | Action::ForeignShell { .. }
            | Action::Net { .. }
            | Action::Fetch { .. }
            | Action::WebSearch { .. }
            | Action::McpTool { .. }
            | Action::UnknownTool { .. }
    )
}
