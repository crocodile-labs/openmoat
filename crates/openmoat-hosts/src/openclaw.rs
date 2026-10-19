//! OpenClaw: the `before_tool_call` plugin hook.
//!
//! OpenClaw has no command hook; a plugin's `before_tool_call` handler sees each
//! tool call before it runs (<https://docs.openclaw.ai/plugins/hooks/tool-policy>).
//! OpenMoat's plugin (`integrations/openclaw/openmoat.mjs` in the CLI crate) runs
//! `moat guard --host openclaw` with this JSON on stdin:
//! `hook_event_name` (`before_tool_call`), OpenClaw's own `toolName`, `params`,
//! `toolCallId`, `runId`, `toolKind`, `sessionId`, `sessionKey` and `agentId`,
//! and four fields the plugin adds: `cwd` (the agent's workspace, where
//! OpenClaw resolves relative paths), `configPath` (the `openclaw.json` the
//! Gateway reads), `stateDir` (its state directory) and `platform` (Node's
//! `process.platform`).
//!
//! Output: nothing for `defer`, else `{"decision": "allow" | "ask" | "deny",
//! "reason"}`. The plugin returns no decision for `allow`, `requireApproval`
//! for `ask` (OpenClaw asks the person and blocks when no one can answer) and
//! `block` for `deny`; anything else it cannot read blocks the call.

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::{HookEvent, HookRequest, Host, HostError};

mod tools;

pub(crate) const EVENT: &str = "before_tool_call";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    tool_name: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
    #[serde(default)]
    tool_kind: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    config_path: Option<String>,
    #[serde(default)]
    state_dir: Option<String>,
    #[serde(default)]
    platform: Option<String>,
}

/// What [`tools::map`] needs to know about one call besides its name and params.
pub(super) struct Call<'a> {
    pub tool: &'a str,
    pub params: &'a Value,
    pub tool_kind: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub state_dir: Option<&'a str>,
    pub windows: bool,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    if p.tool_name.is_empty() {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "toolName",
        });
    }
    let cwd = p.cwd.filter(|c| !c.is_empty());
    let call = Call {
        tool: &p.tool_name,
        params: &p.params,
        tool_kind: p.tool_kind.as_deref(),
        cwd: cwd.as_deref(),
        config_path: p.config_path.as_deref().filter(|c| !c.is_empty()),
        state_dir: p.state_dir.as_deref().filter(|c| !c.is_empty()),
        windows: p.platform.as_deref() == Some("win32"),
    };
    let action = tools::map(&call)?;
    // `write` replaces the whole file with `content`.
    let content = match (p.tool_name.as_str(), &action) {
        ("write", Some(Action::FsWrite { .. })) => p
            .params
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    // `exec` runs in `workdir` when it names one.
    let cwd = match p.tool_name.as_str() {
        "exec" => tools::workdir(p.params.get("workdir"), cwd),
        _ => cwd,
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id.or(p.session_key)),
        call_id: p.tool_call_id,
        cwd,
        tool: p.tool_name,
        action,
        content,
        event: HookEvent::PreToolUse,
    })
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025): no decision, so OpenClaw's own checks (exec approvals,
    // tool policy) decide, as without OpenMoat.
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    serde_json::json!({
        "decision": decision.verdict.as_str(),
        "reason": crate::reason_line(decision),
    })
    .to_string()
}

#[cfg(test)]
mod tests;
