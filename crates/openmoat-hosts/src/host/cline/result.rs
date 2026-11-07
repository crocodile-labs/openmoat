//! Cline's `tool_result` hook: the file named `PostToolUse`
//! (`HOOK_CONFIG_FILE_EVENT_MAP`), what a call returned, read for injected
//! input (ADR-057; ADR-063, proposed).
//!
//! Checked against `runToolCallEnd` and `toolCallEndContext` in
//! `sdk/packages/core/src/hooks/hook-file-hooks.ts` at `cli-v3.0.74`. The
//! payload carries the call as `tool_result` (`id`, `name`, `input`, `output`,
//! `error`, `durationMs`, `startedAt`, `endedAt`) and again as `postToolUse`
//! (`toolName`, `parameters`, `result`: the output, as a string or as JSON
//! text, `success`, `executionTimeMs`), beside the fields of a `tool_call`.
//!
//! Cline runs the file after the call and waits for it (120 s), and what it
//! prints may stop the run (`cancel`) or add to the model's context
//! (`stopOrContextResultFromControl`). OpenMoat answers it with nothing
//! ([`super::render`]), so the run goes on as it would without the hook, and
//! its script prints nothing for it either.

use serde::Deserialize;
use serde_json::Value;

use super::{Payload, ToolCall};
use crate::{HookEvent, HookRequest, Host, HostError};

/// The event name Cline's payload carries for a `PostToolUse` file.
pub(crate) const EVENT: &str = "tool_result";

/// The call as Cline ran it, with what it returned.
#[derive(Deserialize)]
pub(super) struct ToolResult {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    output: Value,
}

/// The same call as Cline's older hook format names it.
#[derive(Deserialize)]
pub(super) struct PostToolUse {
    #[serde(default)]
    result: Option<String>,
}

/// The request for a `tool_result` payload: the call mapped as a `tool_call`
/// is, so its source reads as the call that ran, with its output.
pub(super) fn parse(host: Host, mut p: Payload) -> Result<HookRequest, HostError> {
    let record = p.tool_result.take().ok_or(HostError::MissingField {
        tool: EVENT.to_owned(),
        field: "tool_result",
    })?;
    let output = match p.post_tool_use.take().and_then(|post| post.result) {
        Some(text) => text,
        None => text_of(&record.output),
    };
    p.tool_call = Some(ToolCall {
        id: record.id,
        name: record.name,
        input: record.input,
    });
    let mut request = super::parse(host, p)?;
    request.event = HookEvent::PostToolUse { output };
    Ok(request)
}

/// `output` as text: a string as it is, anything else as its JSON, which is
/// what Cline puts in `postToolUse.result`.
fn text_of(output: &Value) -> String {
    match output {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}
