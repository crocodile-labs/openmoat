//! Gemini CLI (`gemini`, npm `@google/gemini-cli`): the `BeforeTool` command hook.
//!
//! Hook docs: <https://geminicli.com/docs/hooks/reference/>; behaviour checked
//! against the source of `@google/gemini-cli` 0.65.0 (`hooks/hookRunner.js`,
//! `hooks/types.js`, `scheduler/hook-utils.js`, `scheduler/scheduler.js` in
//! `packages/core`), 2026-10-20.
//!
//! Input is JSON on stdin: `session_id`, `transcript_path`, `cwd`,
//! `hook_event_name` (`BeforeTool`), `timestamp`, `tool_name`, `tool_input`,
//! and for an MCP tool `mcp_context` (`server_name`, `tool_name`, …).
//! Output is JSON on stdout: `{"decision": "deny", "reason"}` blocks the call
//! and sends `reason` to the model; `"ask"` makes Gemini CLI confirm the call
//! with the person even where its own policy would not (YOLO and auto-edit
//! included); nothing at all leaves the call to Gemini CLI's own policy, and
//! so does `"allow"`, which skips none of its prompts. Exit 2 also blocks.
//!
//! Gemini CLI has no fail-closed setting. A hook that times out, or is killed
//! by a signal, or exits 1, is a warning and the call runs; a hook that exits
//! with any other code and prints something blocks it (a missing binary exits
//! 127 from the shell). `moat guard` itself turns a panic into a deny.

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    Asks, HookFormat, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile, McpSpec, McpServersJson, Prefixed,
    ProjectSettingsSpec, SettingsFormat, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod doc;
mod settings;
mod tools;

/// The one event OpenMoat answers.
pub(crate) const EVENT: &str = "BeforeTool";

/// `*` matches every tool name, MCP tools included (`hookPlanner.js`
/// `matchesContext`). Gemini CLI takes the timeout in milliseconds; the
/// installer converts ([`HookFormat::Gemini`]).
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "*", TOOL_HOOK_TIMEOUT_S, false)];

/// Gemini CLI puts an `ask` to the person itself.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "gemini-cli",
    display_name: "Gemini CLI",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "runs the call when the hook times out, is killed by a signal or exits 1 \
         (Gemini CLI has no fail-closed setting); blocks it when the hook exits 2, or exits \
         with any other code and prints something, as a missing `openmoat` does",
    gaps: "no OS sandbox from OpenMoat; in a folder Gemini CLI does not trust it runs no \
         settings hooks at all and asks the person before every tool instead; a project's \
         `.gemini/settings.json` can turn hooks off or add a hook that rewrites a call's \
         arguments (`openmoat status` and `doctor` warn about one); extension hooks run beside \
         OpenMoat's; a hook that times out lets the call run",
    // `GEMINI_CLI_HOME` replaces the home directory `.gemini` is looked up in
    // (`homedir()` in `packages/core/src/utils/paths.ts`).
    install: Some(InstallSpec {
        dir_variable: "GEMINI_CLI_HOME",
        dir_name: ".gemini",
        config_file: "settings.json",
        hooks: HOOKS,
        hook_format: HookFormat::Gemini,
        relaxed_keys: settings::RELAXED_KEYS,
        ..InstallSpec::BASE
    }),
    // <https://geminicli.com/docs/tools/mcp-server/>: `mcpServers` in the user
    // and the project `settings.json`.
    mcp: Some(McpSpec {
        user_file: McpFile::HookFile,
        user_reader: &McpServersJson,
        project_files: &[(".gemini/settings.json", &McpServersJson)],
        tool_names: &Prefixed,
    }),
    // A trusted folder's `.gemini/settings.json` is merged over the user's:
    // `hooksConfig.disabled` lists are joined, and its `BeforeTool` hooks run
    // beside OpenMoat's and may rewrite a call's arguments (`docs/hooks/`,
    // `config/settingsSchema.ts`, 0.65.0). There is no local file.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".gemini",
        shared: "settings.json",
        local: None,
        hook_dir: None,
        format: SettingsFormat::Gemini,
        user_file: "settings.json",
    }),
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// Gemini CLI's `BeforeTool` hook.
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
        bench::payload(call, at)
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
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    mcp_context: Option<McpContext>,
}

/// What Gemini CLI sends about an MCP tool (`extractMcpContext`): the server's
/// name as configured and the tool's name on that server, which the combined
/// `mcp_<server>_<tool>` name cannot be split back into.
#[derive(Deserialize)]
pub(super) struct McpContext {
    pub server_name: String,
    pub tool_name: String,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    if p.tool_name.is_empty() {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "tool_name",
        });
    }
    let cwd = p.cwd.filter(|c| !c.is_empty());
    let mapped = tools::map(
        &p.tool_name,
        &p.tool_input,
        p.mcp_context.as_ref(),
        cwd.as_deref(),
    )?;
    // `write_file` replaces the whole file with `content`.
    let content = match (p.tool_name.as_str(), &mapped.action) {
        ("write_file", Some(Action::FsWrite { .. })) => p
            .tool_input
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: None,
        cwd,
        tool: mapped.tool.unwrap_or(p.tool_name),
        action: mapped.action,
        content,
        event: HookEvent::PreToolUse,
    })
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025): no output, so Gemini CLI's own policy decides, as
    // without OpenMoat. `allow` changes nothing there either: Gemini CLI reads
    // only `deny` (or `block`) and `ask` from a `BeforeTool` hook.
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    let line = crate::reason_line(decision);
    let mut reply = serde_json::json!({ "decision": decision.verdict.as_str() });
    // `reason` goes to the model with a deny; `systemMessage` is shown to the
    // person, beside the confirmation for an `ask`.
    if decision.verdict != Verdict::Allow {
        reply["reason"] = Value::from(line.as_str());
        reply["systemMessage"] = Value::from(line);
    }
    reply.to_string()
}

#[cfg(test)]
mod tests;
