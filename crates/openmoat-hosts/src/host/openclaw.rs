//! OpenClaw: the `before_tool_call` plugin hook.
//!
//! OpenClaw has no command hook; a plugin's `before_tool_call` handler sees each
//! tool call before it runs (<https://docs.openclaw.ai/plugins/hooks/tool-policy>).
//! OpenMoat's plugin (`host/openclaw/integration/openmoat.mjs`) runs
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

use crate::bench::{Answer, Call as BenchCall, Exit, Place};
use crate::contract::{
    Asks, ExtraFile, GUARD_BUDGET_S, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec,
    Location, McpFile, McpSpec, wrong_event,
};
use crate::wire::owned_file::OwnedFile;
use crate::{HookEvent, HookRequest, Host, HostError};

/// OpenMoat's plugin, which `moat init` writes to
/// `<state dir>/openmoat/openmoat.mjs` with the binary's path filled in.
static PLUGIN: OwnedFile = OwnedFile {
    name: "OpenClaw plugin",
    source: include_str!("openclaw/integration/openmoat.mjs"),
    first_line: "// OpenMoat for OpenClaw.",
};

/// Seconds OpenClaw waits for OpenMoat's `before_tool_call` handler
/// before it blocks the call (`plugins.entries.openmoat.hooks.timeouts`; its
/// own default is 15 s). OpenClaw asks the person after the handler returns,
/// so this only has to outlast the plugin's wait for `moat guard` (45 s,
/// `host/openclaw/integration/openmoat.mjs`), which outlasts
/// [`GUARD_BUDGET_S`].
const HOOK_TIMEOUT_S: u64 = 60;
const _: () = assert!(GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// OpenClaw runs `before_tool_call` for every tool, and blocks the call when
/// the handler throws or times out
/// (<https://docs.openclaw.ai/plugins/hooks/reference>, "Fail closed").
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false)];

/// The variable that moves OpenClaw's state directory.
pub const STATE_DIR_VARIABLE: &str = "OPENCLAW_STATE_DIR";
/// OpenClaw's state directory's name in the home directory.
pub const STATE_DIR_NAME: &str = ".openclaw";
/// OpenClaw's configuration file's name in its state directory.
pub const CONFIG_FILE: &str = "openclaw.json";
/// The plugin's id: the file name of OpenMoat's standalone plugin.
pub const PLUGIN_ID: &str = "openmoat";

mod advisories;
mod bench;
mod doc;
mod location;
mod mcp;
mod protect;
mod tools;

/// OpenClaw puts an `ask` to the person itself (`requireApproval`).
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "openclaw",
    display_name: "OpenClaw",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
        ..Asks::BASE
    },
    on_hook_failure: "blocks the call when OpenMoat's plugin throws or times out (OpenClaw's \
         `before_tool_call` fails closed), and the plugin blocks when `openmoat` is missing, \
         crashes or does not answer; runs the call unchecked when the Gateway does not \
         load the plugin",
    gaps: "no OS sandbox from OpenMoat; a parameter rewrite by another plugin and \
         OpenClaw's process input are not checked; calls run unchecked if the Gateway does \
         not load the plugin; a failed or slow hook blocks the call",
    // The state directory, which holds `openclaw.json` unless
    // `OPENCLAW_CONFIG_PATH` puts it elsewhere
    // (<https://docs.openclaw.ai/help/environment>).
    install: Some(InstallSpec {
        dir_variable: STATE_DIR_VARIABLE,
        dir_name: STATE_DIR_NAME,
        config_file: CONFIG_FILE,
        hooks: HOOKS,
        hook_file: HookLayout::Plugin(&PLUGIN),
        location: Location::Custom(&location::LOCATE),
        pinned_form: Some(location::pinned_form),
        // OpenMoat's plugin, which OpenClaw loads from `plugins.load.paths`.
        extra_files: &[ExtraFile::InConfigDir(&["openmoat", "openmoat.mjs"])],
        ..InstallSpec::BASE
    }),
    // <https://docs.openclaw.ai/tools/mcp>: "Server definitions live under
    // `mcp.servers`"; the documentation names no project file of them.
    mcp: Some(McpSpec {
        user_file: McpFile::HookFile,
        user_reader: &mcp::OpenClawJson,
        project_files: &[],
        tool_names: &mcp::OpenClawNames,
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    ..HostSpec::BASE
};

pub(crate) const EVENT: &str = "before_tool_call";

/// What OpenMoat's plugin sends from `before_tool_call`.
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

    fn bench_payload(&self, call: &BenchCall, at: &Place<'_>) -> Option<String> {
        Some(bench::payload(call, at))
    }

    fn read_reply(&self, _call: &BenchCall, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit)
    }

    fn seen(&self, _call: &BenchCall, verdict: Verdict) -> Answer {
        bench::seen(verdict)
    }
}

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
