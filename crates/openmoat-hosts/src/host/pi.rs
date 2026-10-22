//! pi (`@earendil-works/pi-coding-agent`, earlier `@mariozechner/pi-coding-agent`):
//! the `tool_call` extension event.
//!
//! pi has no command hook; an extension's `tool_call` handler sees each tool
//! call before it runs and blocks it by returning `{ block: true, reason }`, and
//! a handler that throws blocks the call too (pi 1.3.0 `docs/extensions.md`,
//! "Errors and cleanup"; `dist/core/agent-session.js` `_beforeToolCall`).
//! OpenMoat's extension (`integrations/pi/openmoat.js` in the CLI crate) runs
//! `moat guard --host pi` with this JSON on stdin: `hook_event_name`
//! (`tool_call`), pi's own `toolName`, `input`, `toolCallId` and
//! `parentToolCallId`, and four fields the extension adds: `sessionId` (from
//! `ctx.sessionManager`), `cwd` (`ctx.cwd`, where pi's tools resolve relative
//! paths), `hasUI` (`ctx.hasUI`: whether pi can show a dialog) and `platform`
//! (Node's `process.platform`). Checked against pi 1.3.0 (npm, 2026-10-15).
//!
//! Output: nothing for `defer`, else `{"decision": "allow" | "ask" | "deny",
//! "reason"}`. The extension returns nothing for `allow`, asks the person with
//! `ctx.ui.confirm` for `ask`, and blocks for `deny`; anything else it cannot
//! read blocks the call.

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call as BenchCall, Exit, Place};
use crate::contract::{
    Asks, GUARD_BUDGET_S, HookDir, HookFormat, HookSpec, HostAdapter, HostSpec, InstallSpec,
    McpFile, McpSpec, McpServersJson, ProjectSettingsSpec, SettingsFormat, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod doc;
mod mcp;
mod tools;

/// Seconds OpenMoat's extension waits for `moat guard` before it blocks the
/// call (`GUARD_TIMEOUT_MS` in `integrations/pi/openmoat.js`, which the CLI's
/// tests compare with this). pi itself waits for a `tool_call` handler without
/// a limit, and a person's answer to an `ask` comes after this wait.
pub(crate) const HOOK_TIMEOUT_S: u64 = 45;
const _: () = assert!(GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// pi runs `tool_call` for every tool, nested calls a tool makes through
/// `ctx.executeTool` included, and blocks the call when a handler throws.
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false)];

pub(crate) const EVENT: &str = "tool_call";

/// pi asks through the extension's dialog where it has a screen (`ctx.hasUI`:
/// the terminal UI and RPC mode); print and JSON modes have none.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "pi",
    display_name: "pi",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("pi runs without a screen to ask on (print or JSON mode)"),
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "blocks the call when OpenMoat's extension throws (pi's `tool_call` \
         fails closed), and the extension blocks when `openmoat` is missing, crashes or \
         does not answer within 45 s; runs the call unchecked when pi does not load the \
         extension (`--no-extensions`, or an `extensions` entry in pi's or a trusted \
         project's settings that turns it off)",
    gaps: "no OS sandbox from OpenMoat; pi has no approval step of its own, so a call \
         OpenMoat defers runs; an input change by an extension pi loads after OpenMoat's \
         (a package's) and an extension that replaces a built-in tool are not checked; \
         a trusted project's `.pi` settings and extensions load with the agent's rights; \
         calls run unchecked if pi does not load the extension (`openmoat status` and \
         `doctor` report a settings entry that turns it off, not `--no-extensions`); a \
         failed or slow hook blocks the call",
    // The agent directory, `~/.pi/agent` unless `PI_CODING_AGENT_DIR` moves it;
    // pi loads every `.js` and `.ts` file in its `extensions/` on start
    // (pi 1.3.0 `docs/configuration.md`, `docs/environment-variables.md`).
    install: Some(InstallSpec {
        dir_variable: "PI_CODING_AGENT_DIR",
        dir_name: ".pi/agent",
        config_file: "extensions/openmoat.js",
        hooks: HOOKS,
        hook_format: HookFormat::Pi,
        ..InstallSpec::BASE
    }),
    // pi reads `<agent dir>/mcp.json` and a trusted project's `.pi/mcp.json`,
    // `{"mcpServers": {…}}`, and names a server's tools `mcp__<server>__<tool>`
    // with every character but letters, digits and `_` as `_` (`docs/mcp.md`).
    mcp: Some(McpSpec {
        user_file: McpFile::InConfigDir("mcp.json"),
        user_reader: &McpServersJson,
        project_files: &[(".pi/mcp.json", &McpServersJson)],
        tool_names: &mcp::Underscored,
    }),
    // A trusted project's `.pi/settings.json` can turn the user's extensions
    // off and add packages, and its `.pi/extensions/` load with the agent's
    // rights; the user's `settings.json` can turn OpenMoat's extension off
    // with an `extensions` entry (`docs/settings.md`, "Resources";
    // `dist/core/package-manager.js` `isEnabledByOverrides`). Writes to the
    // project files ask (`runs-later` in the default policy).
    project_settings: Some(ProjectSettingsSpec {
        dir: ".pi",
        shared: "settings.json",
        local: None,
        hook_dir: Some(HookDir {
            path: ".pi/extensions",
            extensions: &["js", "ts"],
        }),
        format: SettingsFormat::Pi,
        user_file: "settings.json",
    }),
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// What OpenMoat's extension sends from `tool_call`.
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
        bench::payload(call, at)
    }

    fn read_reply(&self, _call: &BenchCall, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    tool_name: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default, rename = "hasUI")]
    has_ui: bool,
    #[serde(default)]
    platform: Option<String>,
}

/// What [`tools::map`] needs to know about one call besides its name and input.
pub(super) struct Call<'a> {
    pub tool: &'a str,
    pub input: &'a Value,
    pub cwd: Option<&'a str>,
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
        input: &p.input,
        cwd: cwd.as_deref(),
        windows: p.platform.as_deref() == Some("win32"),
    };
    let action = tools::map(&call)?;
    // `write` replaces the whole file with `content`.
    let content = match p.tool_name.as_str() {
        "write" => p
            .input
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    // Without a screen an `ask` cannot be put to the person (`Asks::on_no_ask`).
    let event = if p.has_ui {
        HookEvent::PreToolUse
    } else {
        HookEvent::PreToolUseNoAsk
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id.filter(|s| !s.is_empty())),
        call_id: p.tool_call_id,
        cwd,
        tool: p.tool_name,
        action,
        content,
        event,
    })
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025): no decision, so pi runs the call as it would without
    // OpenMoat; pi has no approval step of its own.
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
