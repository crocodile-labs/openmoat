//! GitHub Copilot CLI (`copilot`, npm `@github/copilot`): its `preToolUse`
//! command hook, in the camelCase format.
//!
//! Hooks: <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>
//! and <https://docs.github.com/en/copilot/reference/hooks-configuration>, checked
//! against `@github/copilot` 1.0.101 (its `changelog.json`, the SDK's
//! `types.d.ts` and the runtime's own messages), 2026-10-20.
//!
//! Input is JSON on stdin: `sessionId`, `timestamp`, `cwd`, `toolName` and
//! `toolArgs`, which the CLI sends as a JSON string (an object is read too).
//! Output is `{"permissionDecision": "allow" | "deny" | "ask",
//! "permissionDecisionReason"}`; empty output leaves the call to Copilot's own
//! permission flow, and exit 2 denies whatever stdout says. Any other non-zero
//! exit denies too ("hook errored", since 1.0.57), but a hook that outlives its
//! `timeoutSec` is killed and the call goes on: timeouts fail open for every
//! event. `ask` prompts in an interactive session; autopilot and the cloud
//! agent turn it into a deny.
//!
//! The user hook files are every `*.json` in `~/.copilot/hooks/` (or
//! `$COPILOT_HOME/hooks/`), so OpenMoat's entry lives in a file of its own.

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    Asks, HookDir, HookFormat, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile, 
    McpSpec, McpServersJson, ProjectSettingsSpec, SettingsFormat, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod doc;
mod mcp;
mod tools;

/// The event name in camel case, whose payload has camel-case fields.
/// `PreToolUse` sends Claude Code's field and tool names instead, which this
/// adapter does not read.
pub(crate) const EVENT: &str = "preToolUse";

/// One entry for every tool: the hook payload does not mark MCP tools, so a
/// matcher could not list them. 600 s is far above the guard's own budget, so
/// a slow guard denies before Copilot's fail-open timeout is reached.
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", TOOL_HOOK_TIMEOUT_S, false)];

pub(crate) static SPEC: HostSpec = HostSpec {
    id: "copilot-cli",
    display_name: "GitHub Copilot CLI",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "blocks the call when the hook cannot start, crashes or exits non-zero; \
         runs it when the hook times out (`timeoutSec`, 600 s as `openmoat init` writes it) \
         or its file is gone",
    gaps: "a hook that times out lets the call run; `disableAllHooks` in Copilot's user or a \
         repository's `settings.json` turns the hook off (`openmoat status` and `doctor` \
         report it); MCP tools are told apart from built-in ones only by name, so a changed \
         server is traced by its `<server>-` prefix; asks become denies in autopilot; no OS \
         sandbox is configured",
    install: Some(InstallSpec {
        dir_variable: "COPILOT_HOME",
        dir_name: ".copilot",
        config_file: "hooks/openmoat.json",
        hooks: HOOKS,
        hook_format: HookFormat::Copilot,
        ..InstallSpec::BASE
    }),
    // `mcp-config.json` in the configuration directory, and a project's
    // `.mcp.json` and `.github/mcp.json` from the working directory up to the
    // repository root, which may list the servers bare
    // (<https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers>).
    mcp: Some(McpSpec {
        user_file: McpFile::InConfigDir("mcp-config.json"),
        user_reader: &McpServersJson,
        project_files: &[
            (".mcp.json", &mcp::JsonOrBare),
            (".github/mcp.json", &mcp::JsonOrBare),
        ],
        tool_names: &mcp::Dashed,
    }),
    // A repository's settings are merged over the user's, and
    // `disableAllHooks: true` there skips the user hook files too. Its
    // `.github/hooks/*.json` load once the folder is trusted and run their
    // commands outside any sandbox OpenMoat sets up. The user's
    // `settings.json` turns every hook off with the same key.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".github/copilot",
        shared: "settings.json",
        local: Some("settings.local.json"),
        hook_dir: Some(HookDir {
            path: ".github/hooks",
            extensions: &["json"],
        }),
        format: SettingsFormat::ClaudeCode,
        user_file: "settings.json",
    }),
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// Copilot CLI's camelCase `preToolUse`.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// The camelCase payload names no event; a payload that names one other
    /// than `preToolUse` is not this hook's.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None | Some(EVENT) => parse(host, payload),
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_args: Value,
}

fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let args = arguments(&p.tool_name, p.tool_args)?;
    let action = tools::action(&p.tool_name, &args, p.cwd.as_deref())?;
    // `create` writes the whole file from `file_text`.
    let content = match p.tool_name.as_str() {
        "create" => args
            .get("file_text")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: p.tool_call_id,
        cwd: p.cwd.filter(|c| !c.is_empty()),
        tool: p.tool_name,
        action,
        content,
        event: HookEvent::PreToolUse,
    })
}

/// `toolArgs` as a value: the CLI sends it as a JSON string, which is parsed;
/// an `apply_patch` call may carry its patch text there instead. Text that is
/// not JSON for any other tool cannot be checked, so it is an error.
fn arguments(tool: &str, args: Value) -> Result<Value, HostError> {
    let Value::String(text) = args else {
        return Ok(args);
    };
    match serde_json::from_str(&text) {
        Ok(parsed) => Ok(parsed),
        Err(_) if tool == "apply_patch" => Ok(Value::String(text)),
        Err(e) => Err(HostError::MalformedArguments {
            tool: tool.to_owned(),
            problem: format!("`toolArgs` is not JSON: {e}"),
        }),
    }
}

/// `defer` (ADR-025) is no decision: empty stdout and exit 0 leave the call to
/// Copilot's own permission flow.
fn render(decision: &Decision) -> String {
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    serde_json::json!({
        "permissionDecision": decision.verdict.as_str(),
        "permissionDecisionReason": crate::reason_line(decision),
    })
    .to_string()
}

#[cfg(test)]
mod tests;
