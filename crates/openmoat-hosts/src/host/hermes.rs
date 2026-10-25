//! Hermes Agent (`hermes`, Nous Research): its `pre_tool_call` shell hook.
//!
//! Hooks: <https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks>;
//! behaviour checked against the source of `NousResearch/hermes-agent` v0.22.5
//! (`agent/shell_hooks.py`, `hermes_cli/plugins.py`, `tools/approval.py`,
//! `model_tools.py`, `agent/tool_executor.py`), 2026-10-25.
//!
//! The hook is an entry of `hooks.pre_tool_call` in the profile's
//! `config.yaml`. Hermes runs its `command` (split like a shell line, no shell)
//! with this JSON on stdin: `hook_event_name` (`pre_tool_call`), `tool_name`,
//! `tool_input`, `session_id` (may be empty), `cwd` (the Hermes process's
//! working directory, not the session's), `profile` and `extra`, which holds
//! `task_id`, `tool_call_id`, `turn_id`, `api_request_id` and
//! `middleware_trace`. The Tool Search bridge's `tool_call` is unwrapped
//! before the hook, so it sees the tool that runs.
//!
//! Output is JSON on stdout: `{"decision": "block", "reason"}` blocks the call
//! with `reason` as its result, and so does exit 2; `{"action": "approve",
//! "message", "rule_key"}` sends the call to Hermes's own approval prompt (the
//! terminal, or the gateway's buttons), which blocks on a denial, a timeout or
//! when no person is there, but approves it unseen in YOLO mode, with
//! `approvals.mode: off`, and in cron, single-query or unattended sessions set
//! to `approve`; no output, or `{}`, makes no decision. `rule_key` names what Hermes's
//! "always" remembers: without it, the whole tool.
//!
//! With `fail_closed: true` a hook that cannot start, times out, exits other
//! than 0 with no decision or prints something that is not a JSON object
//! blocks the call; without it each of those lets the call run.

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    Asks, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, Location, McpFile, McpSpec,
    Unseen, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod consent;
mod doc;
pub(crate) mod hook_file;
mod location;
mod mcp;
mod protect;
mod settings;
mod tools;

/// The one event OpenMoat answers.
pub(crate) const EVENT: &str = "pre_tool_call";

/// Seconds Hermes waits for the hook (its own default; it clamps a value
/// above 300). Hermes asks the person after the hook returns, so the hook
/// never waits on one; a timed-out hook blocks the call (`fail_closed`).
/// `plugins.hook_callback_timeout` (30 s by default) also bounds it, and
/// blocks the call too when it runs out.
const HOOK_TIMEOUT_S: u64 = 60;
const _: () = assert!(crate::GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// No matcher: the hook runs for every tool, MCP tools included. The entry
/// sets `fail_closed` itself ([`hook_file::Hermes`]).
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false)];

/// Hermes puts an `ask` to the person itself, except where it would approve
/// it unseen ([`Unseen`]): there the ask is a deny.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "hermes",
    display_name: "Hermes Agent",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some(
            "Hermes Agent would run it without asking you (`HERMES_YOLO_MODE`, \
             `approvals.mode: off`, or a cron, single-query or unattended mode set to `approve`)",
        ),
        defer_is_ask_on_no_ask: false,
        unseen: Some(Unseen {
            env: &["HERMES_YOLO_MODE"],
            config: settings::approves_unseen,
        }),
        ..Asks::BASE
    },
    on_hook_failure: "blocks the call when the hook cannot start, times out, exits non-zero \
         without a decision or prints something that is not JSON (`fail_closed: true`, which \
         `openmoat init` sets); runs every call unchecked when the hook is not registered: \
         missing from `config.yaml` or from `shell-hooks-allowlist.json` in a gateway, cron or \
         ACP session, another profile, or `HERMES_SAFE_MODE=1`",
    gaps: "no OS sandbox from OpenMoat; what an `execute_code` script does itself is not \
         checked (its tool calls are); a plugin, another hook's `modify` or tool middleware can \
         rewrite a call's arguments after the check; terminal commands on a remote backend \
         (docker, ssh, modal, …) are checked as local ones; the in-session `/yolo` toggle and \
         `hermes -z` approve an ask unseen without OpenMoat seeing it; relative paths are \
         checked against the Hermes process's directory, not the session's; another profile, \
         or `HERMES_SAFE_MODE=1`, runs without the hook; a changed `config.yaml` is caught on \
         the next call",
    install: Some(InstallSpec {
        dir_variable: location::HOME_VARIABLE,
        dir_name: location::DIR_NAME,
        config_file: CONFIG_FILE,
        hooks: HOOKS,
        hook_file: HookLayout::Yaml(&hook_file::Hermes),
        location: Location::Custom(&location::LOCATE),
        pinned_form: Some(settings::pinned_form),
        consent: Some(&consent::ALLOWLIST),
        ..InstallSpec::BASE
    }),
    // `mcp_servers` in the profile's `config.yaml`
    // (<https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp>);
    // Hermes reads no project file of servers.
    mcp: Some(McpSpec {
        user_file: McpFile::HookFile,
        user_reader: &mcp::McpServersYaml,
        project_files: &[],
        tool_names: &mcp::HermesNames,
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// Hermes's configuration file in its home (or a profile's) directory.
pub(crate) const CONFIG_FILE: &str = "config.yaml";

/// Hermes Agent's `pre_tool_call` shell hook.
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
            Some(EVENT) => parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        render(decision)
    }

    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        Some(bench::payload(call, at))
    }

    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit)
    }

    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        bench::seen(verdict)
    }
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    extra: Value,
}

fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let tool = p
        .tool_name
        .filter(|t| !t.is_empty())
        .ok_or(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "tool_name",
        })?;
    // Hermes sends `null` for arguments that are not an object; the hook's
    // own call always has an object (`_get_pre_tool_call_directive_details`).
    if !p.tool_input.is_object() {
        return Err(HostError::MalformedArguments {
            tool,
            problem: "`tool_input` is not an object".to_owned(),
        });
    }
    let action = tools::action(&tool, &p.tool_input)?;
    // `write_file` replaces the whole file with `content`.
    let content = match tool.as_str() {
        "write_file" => p
            .tool_input
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    let call_id = p
        .extra
        .get("tool_call_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id.filter(|s| !s.is_empty())),
        call_id,
        cwd: p.cwd.filter(|c| !c.is_empty()),
        tool,
        action,
        content,
        event: HookEvent::PreToolUse,
    })
}

/// Nothing for `defer` (ADR-025) and `{}` for `allow`: Hermes reads neither as
/// a decision and has no "allow" that skips its own checks, so both leave the
/// call to them, as without OpenMoat. An `ask` goes to Hermes's approval prompt
/// with a `rule_key` of its own reason, so Hermes's "always" approves that ask
/// again, never the whole tool; a `deny` blocks.
pub(crate) fn render(decision: &Decision) -> String {
    let line = crate::reason_line(decision);
    match decision.verdict {
        Verdict::Defer => String::new(),
        Verdict::Allow => "{}".to_owned(),
        Verdict::Ask => serde_json::json!({
            "action": "approve",
            "message": line,
            "rule_key": rule_key(decision),
        })
        .to_string(),
        // `Deny`, and any verdict added to the core later, blocks the call.
        _ => serde_json::json!({ "decision": "block", "reason": line }).to_string(),
    }
}

/// `openmoat:` and a stable hash of the decision's rules and reasons, which
/// name what the call does: the grain at which Hermes's "always" approves.
fn rule_key(decision: &Decision) -> String {
    // FNV-1a, 64 bits: the same key from every build, so an "always" a
    // person gave survives an OpenMoat upgrade.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in decision.rules.iter().chain(&decision.reasons) {
        for byte in part.bytes().chain([0]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("openmoat:{hash:016x}")
}

#[cfg(test)]
mod tests;
