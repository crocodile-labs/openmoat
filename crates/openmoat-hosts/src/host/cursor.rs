//! Cursor hooks: `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`
//! and `preToolUse`.
//!
//! Input is JSON on stdin with per-event fields plus `workspace_roots`. Output is
//! `{"permission": "allow" | "deny" | "ask", "user_message", "agent_message"}`;
//! exit 2 also denies. Only the shell and MCP events prompt on `ask`; elsewhere
//! [`Host::answer`] sends it as a deny. Cursor is fail-open unless the hook entry sets
//! `failClosed`, which the installer does.

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    Asks, HookFormat, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile, McpLayout, McpSpec,
    SandboxFormat, SandboxSpec, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod pre_tool;

use pre_tool::pre_tool_action;

/// Cursor blocks a failed hook through `failClosed` on every entry
/// ([`HookFormat::Cursor`]), not through `block_on_failure`.
const HOOKS: &[HookSpec] = &[
    HookSpec::new("beforeShellExecution", "", TOOL_HOOK_TIMEOUT_S, false),
    HookSpec::new("beforeMCPExecution", "", TOOL_HOOK_TIMEOUT_S, false),
    HookSpec::new("beforeReadFile", "", TOOL_HOOK_TIMEOUT_S, false),
    HookSpec::new("preToolUse", "", TOOL_HOOK_TIMEOUT_S, false),
];

/// `preToolUse` accepts `ask` but runs the call, and `beforeReadFile` takes
/// only allow or deny; both run file tools outside Cursor's sandbox, so a
/// `defer` there is an `ask`. Only file tools reach these hooks, and
/// `moat allow --last` approves the exact file.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "cursor",
    display_name: "Cursor",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Cursor does not prompt for this hook"),
        defer_is_ask_on_no_ask: true,
    },
    on_hook_failure: "runs the call when the hook is missing, crashes or times out, unless \
         the hook entry sets `failClosed: true`; then it blocks the call",
    gaps: "commands Cursor runs outside its sandbox (a rerun or call its Auto-review \
         classifier approves, Run Everything mode, the CLI without `--sandbox enabled`) \
         are not confined; file-tool asks become denies; Task and tools that name no path \
         are not hooked; a failed hook blocks the call",
    install: Some(InstallSpec {
        dir_variable: "CURSOR_CONFIG_DIR",
        dir_name: ".cursor",
        config_file: "hooks.json",
        hooks: HOOKS,
        hook_format: HookFormat::Cursor,
    }),
    mcp: Some(McpSpec {
        user_file: McpFile::BesideHookFile("mcp.json"),
        user_layout: McpLayout::Json,
        project_file: Some((".cursor/mcp.json", McpLayout::Json)),
    }),
    // Cursor documents its sandbox for macOS and Linux only.
    sandbox: Some(SandboxSpec {
        format: SandboxFormat::CursorSandbox,
        file: "sandbox.json",
        unavailable_on_windows: Some(
            "Cursor's sandbox runs on macOS and Linux only; the hook still applies the policy",
        ),
    }),
};

/// Cursor's hooks, each named in the payload.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            Some(event) if EVENTS.contains(&event) => parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        render(decision)
    }

    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        bench::payload(call, at)
    }

    fn read_reply(&self, call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(call, exit)
    }

    fn seen(&self, call: &Call, verdict: Verdict) -> Answer {
        bench::seen(call, verdict)
    }
}

pub(crate) const EVENTS: &[&str] = &[
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
];

#[derive(Deserialize)]
struct Payload {
    hook_event_name: String,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    generation_id: Option<String>,
    #[serde(default)]
    workspace_roots: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    mcp_server_name: Option<String>,
    #[serde(default)]
    tool_use_id: Option<String>,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let event = p.hook_event_name.as_str();
    let required = |value: Option<String>, field: &'static str| {
        value
            .filter(|v| !v.is_empty())
            .ok_or(HostError::MissingField {
                tool: event.to_owned(),
                field,
            })
    };
    let cwd = p
        .cwd
        .filter(|c| !c.is_empty())
        .or_else(|| p.workspace_roots.first().cloned());
    let (tool, action) = match event {
        "beforeShellExecution" => (
            "Shell".to_owned(),
            Some(Action::Shell {
                command: required(p.command, "command")?,
            }),
        ),
        "beforeMCPExecution" => {
            let tool = required(p.tool_name, "tool_name")?;
            let server = p.mcp_server_name.unwrap_or_else(|| "unknown".to_owned());
            let name = format!("mcp__{server}__{tool}");
            let action = crate::wire::mcp::action(&name, &p.tool_input)?;
            (name, Some(action))
        }
        "beforeReadFile" => (
            "Read".to_owned(),
            Some(Action::FsRead {
                path: required(p.file_path, "file_path")?,
            }),
        ),
        "preToolUse" => {
            let tool = required(p.tool_name, "tool_name")?;
            let action = pre_tool_action(&tool, &p.tool_input, cwd.as_deref())?;
            (tool, action)
        }
        other => return Err(HostError::WrongEvent(other.to_owned())),
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.conversation_id),
        call_id: p.tool_use_id.or(p.generation_id),
        cwd,
        tool,
        action,
        content: None,
        event: event_kind(event),
    })
}

/// <https://cursor.com/docs/hooks> lists `ask` as an output of
/// `beforeShellExecution` and `beforeMCPExecution` and shows a shell hook using it
/// to ask for permission. For `preToolUse` it says `ask` is "accepted by the schema
/// but not enforced", and `beforeReadFile`'s output is only allow or deny. Any
/// event not known to prompt is treated as one that does not.
fn event_kind(event: &str) -> HookEvent {
    match event {
        "beforeShellExecution" | "beforeMCPExecution" => HookEvent::PreToolUse,
        _ => HookEvent::PreToolUseNoAsk,
    }
}

pub(crate) fn render(decision: &Decision) -> String {
    // Cursor's hooks have no "no decision" (ADR-025): `defer` reaches only the shell
    // and MCP events ([`Host::decided`]), where it is Cursor's own prompt.
    let verdict = match decision.verdict {
        Verdict::Defer => Verdict::Ask,
        verdict => verdict,
    };
    // Each `Value` always renders, unlike serializing a struct; the members
    // keep the order the hooks documentation shows.
    let permission = Value::from(verdict.as_str());
    let message = Value::from(crate::reason_line(decision));
    format!(r#"{{"permission":{permission},"user_message":{message},"agent_message":{message}}}"#)
}

#[cfg(test)]
mod tests;
