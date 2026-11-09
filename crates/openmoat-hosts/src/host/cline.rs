//! Cline (npm `cline`, the `cline` command): its `PreToolUse` file hook, and
//! its `PostToolUse` file for what a call returned ([`result`]).
//!
//! Behaviour checked against the source of `cline/cline` at tag `cli-v3.0.74`
//! (2026-10-26; the SDK files below are the same at `v4.1.26`), 2026-11-03:
//! `sdk/packages/core/src/hooks/hook-file-config.ts`, `hook-file-hooks.ts`,
//! `subprocess-runner.ts`, `sdk/packages/shared/src/storage/paths.ts` and
//! `sdk/packages/agents/src/agent-runtime.ts`.
//!
//! Cline has no hook entries in a settings file: every file named after a
//! hook event in a hooks directory is that event's hook, and a file named
//! `PreToolUse` (no extension, or `.sh`, `.py`, `.js`, …) runs before every
//! tool call (`HOOK_CONFIG_FILE_EVENT_MAP`: `PreToolUse` → `tool_call`). The
//! directories are `~/Documents/Cline/Hooks`, `$CLINE_DIR/hooks` (`~/.cline`
//! unless `CLINE_DIR` moves it) and a workspace's `.clinerules/hooks` and
//! `.cline/hooks` (`resolveHooksConfigSearchPaths`). A file is run with the
//! interpreter its `#!` line names (`inferHookCommand`), in the workspace,
//! with this JSON on stdin: `hookName` (`tool_call`), `clineVersion`,
//! `timestamp`, `taskId`, `sessionContext.rootSessionId`, `workspaceRoots`,
//! `userId`, `agent_id`, `parent_agent_id`, `iteration`, `tool_call` (`id`,
//! `name`, `input`: the tool's arguments as the model gave them) and
//! `preToolUse` (`toolName`, `parameters`: the same arguments as strings).
//!
//! Cline reads only stdout, never the exit code (`runBlockingHookCommands`):
//! `{"cancel": true, "errorMessage"}` stops the call before it runs and ends
//! the run with `errorMessage` as its reason (`beforeToolResultFromControl`,
//! then `applyStopControl` throws `ControlledStopError`); `{}` or nothing is
//! no decision, and Cline's own approval (`requestToolApproval`) runs. Cline's
//! `review` field is read but ignored for a tool call, so a hook cannot prompt. A hook that
//! cannot start, prints something that is not JSON, or is killed after
//! 120 s (`toolCallTimeoutMs ?? 120000`) is logged and the call runs: there is
//! no setting that blocks instead. So OpenMoat's script
//! (`host/cline/integration/PreToolUse.sh`) prints a `cancel` itself when
//! `openmoat` is missing, crashes or answers nothing.

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call as BenchCall, Exit, Place};
use crate::contract::{
    ExtraFile, Reviews, GUARD_BUDGET_S, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec,
    McpFile, McpServersJson, McpSpec, OtherHooks, wrong_event,
};
use crate::wire::owned_file::{OwnedFile, Syntax};
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod doc;
mod mcp;
mod protect;
mod result;
mod tools;

/// The event name Cline's payload carries for a `PreToolUse` file.
pub(crate) const EVENT: &str = "tool_call";

/// Seconds Cline waits for a `PreToolUse` file before it kills it and runs the
/// call (`toolCallTimeoutMs ?? 120000` in `hook-file-hooks.ts`; nothing sets
/// it). Cline cannot prompt, so the hook never waits on a person.
pub(crate) const HOOK_TIMEOUT_S: u64 = 120;
const _: () = assert!(GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// One file, run for every tool; Cline has no matcher.
const HOOKS: &[HookSpec] = &[HookSpec::new("PreToolUse", "", HOOK_TIMEOUT_S, false)];

/// OpenMoat's hook script, which is Cline's hook file: `moat init` writes it to
/// `<config dir>/hooks/PreToolUse` with the binary's path filled in, and the
/// same script to `hooks/PostToolUse`, where it never stops the run.
static SCRIPT: OwnedFile = OwnedFile {
    name: "Cline hook script",
    source: include_str!("cline/integration/PreToolUse.sh"),
    first_line: "#!/bin/sh\n# OpenMoat for Cline.",
    syntax: Syntax::PosixShell,
};

/// Cline's hooks cannot prompt: a `review` reaches it as a deny.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "cline",
    display_name: "Cline CLI",
    reviews: Reviews {
        on_pre_tool_use: Some("Cline's hooks cannot prompt (Cline ignores a hook's `review` field)"),
        ..Reviews::BASE
    },
    on_hook_failure: "blocks the call when `openmoat` is missing, crashes or answers nothing \
         (OpenMoat's hook script prints Cline's `cancel` itself); runs the call when the \
         script cannot start (no `sh`, as on native Windows), when Cline kills it after \
         120 s, and when Cline runs no hooks (`--yolo`); Cline has no setting that blocks a \
         failed hook",
    gaps: "the Cline VS Code extension is not covered (it reads hooks only from \
         `~/Documents/Cline/Hooks` and a workspace's `.clinerules/hooks`); no OS sandbox \
         from OpenMoat; `--yolo` runs no hooks, and `--config`, `--hooks-dir` or a moved \
         `CLINE_DIR` that OpenMoat did not install into skip the hook; reviews become denies, \
         and a deny ends Cline's run; Cline approves calls on its own by default \
         (`--auto-approve`), so a call OpenMoat defers usually runs; another `PreToolUse` \
         file or plugin can rewrite a call's input (`overrideInput`) after OpenMoat checked \
         it (`openmoat status` and `doctor` name the ones they find), and a workspace's `.cline/hooks` and `.clinerules/hooks` run with the agent's \
         rights (writing them needs review, `runs-later`); the provider's own `web_search` runs without a hook; on native Windows \
         the script does not run",
    // `$CLINE_DIR/hooks`, `~/.cline` unless `CLINE_DIR` moves it
    // (`resolveClineDir`, `resolveHooksConfigSearchPaths` in `paths.ts`).
    install: Some(InstallSpec {
        dir_variable: "CLINE_DIR",
        dir_name: ".cline",
        config_file: "hooks/PreToolUse",
        hooks: HOOKS,
        hook_file: HookLayout::Script(&SCRIPT),
        // the same script as Cline's `PostToolUse` file, for injected input
        // (ADR-057); the lock pins it with the hook file
        extra_files: &[ExtraFile::InConfigDir(&["hooks", "PostToolUse"])],
        ..InstallSpec::BASE
    }),
    // `<data dir>/settings/cline_mcp_settings.json`, `{"mcpServers": {…}}`,
    // the data directory `$CLINE_DIR/data` (`resolveMcpSettingsPath`; the
    // schema in `extensions/mcp/config-loader.ts`). A server's tools are
    // `<server>__<tool>` (`extensions/mcp/name-transform.ts`), which the
    // adapter records as `mcp__<server>__<tool>`.
    mcp: Some(McpSpec {
        user_file: McpFile::InConfigDir("data/settings/cline_mcp_settings.json"),
        user_reader: &McpServersJson,
        project_files: &[],
        tool_names: &mcp::Spelled,
        auto_start: None,
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    docs: doc::DOCS,
    // The arguments come as `tool_call.input` and again as `preToolUse.parameters`.
    payload_copies: 2,
    limit: Some(
        "`cline --yolo` runs no hooks; another hook or plugin can rewrite a call after \
         OpenMoat checked it; Cline runs the call if OpenMoat's script cannot start or is \
         killed after 120 s",
    ),
    // Every `PreToolUse` file of Cline's hook directories runs, OpenMoat's
    // among them (`resolveHooksConfigSearchPaths`), and so do the plugins in
    // `$CLINE_DIR/plugins`.
    other_hooks: Some(OtherHooks {
        stem: "PreToolUse",
        home_dirs: &["Documents/Cline/Hooks"],
        config_dirs: &["hooks"],
        project_dirs: &[".clinerules/hooks", ".cline/hooks"],
        plugin_dirs: &["plugins"],
        effect: "runs on every Cline tool call beside OpenMoat's hook and can rewrite the \
                 call's input (`overrideInput`) after OpenMoat checked it",
    }),
    tool_token: crate::ToolToken::NotWithheld {
        why: "Cline starts tool commands with `/bin/bash` and the CLI has no setting for it",
    },
    ..HostSpec::BASE
};

/// Cline's `tool_call` file-hook payload.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// Cline names the event in `hookName`; a payload that names one in
    /// `hook_event_name` is another host's.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        if event.is_some() {
            return Err(wrong_event(event));
        }
        let p: Payload = serde_json::from_str(payload)?;
        match p.hook_name.as_deref() {
            Some(EVENT) => parse(host, p),
            Some(result::EVENT) => result::parse(host, p),
            other => Err(wrong_event(other)),
        }
    }

    /// `tool_result` is what a call returned (ADR-057).
    fn event_of(&self, event: &str) -> HookEvent {
        match event {
            result::EVENT => HookEvent::PostToolUse {
                output: String::new(),
            },
            _ => HookEvent::PreToolUse,
        }
    }

    /// Nothing at all for what a call returned, whatever was decided: Cline
    /// would stop the whole run on a `cancel` there.
    fn render(&self, event: &HookEvent, decision: &Decision) -> String {
        match event {
            HookEvent::PostToolUse { .. } => String::new(),
            _ => render(decision),
        }
    }

    fn bench_payload(&self, call: &BenchCall, at: &Place<'_>) -> Option<String> {
        bench::payload(call, at)
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
    #[serde(default)]
    hook_name: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    session_context: Option<SessionContext>,
    #[serde(default)]
    workspace_roots: Vec<String>,
    #[serde(default, rename = "tool_call")]
    tool_call: Option<ToolCall>,
    #[serde(default, rename = "tool_result")]
    tool_result: Option<result::ToolResult>,
    #[serde(default, rename = "postToolUse")]
    post_tool_use: Option<result::PostToolUse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionContext {
    #[serde(default)]
    root_session_id: Option<String>,
}

#[derive(Deserialize)]
struct ToolCall {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Value,
}

/// What [`tools::map`] needs to know about one call besides its name and input.
pub(super) struct Call<'a> {
    pub tool: &'a str,
    pub input: &'a Value,
    pub cwd: Option<&'a str>,
    /// Cline runs `run_commands` with PowerShell on Windows and bash elsewhere
    /// (`getDefaultShell` in `extensions/tools/executors/bash.ts`); the guard
    /// runs on the same machine.
    pub windows: bool,
}

fn parse(host: Host, p: Payload) -> Result<HookRequest, HostError> {
    let call = p.tool_call.ok_or(HostError::MissingField {
        tool: EVENT.to_owned(),
        field: "tool_call",
    })?;
    let name = call
        .name
        .filter(|n| !n.is_empty())
        .ok_or(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "tool_call.name",
        })?;
    // Cline runs the session in its first workspace root (`workspacePath`),
    // where its tools resolve a relative path.
    let cwd = p.workspace_roots.into_iter().next().filter(|c| !c.is_empty());
    let mapped = tools::map(&Call {
        tool: &name,
        input: &call.input,
        cwd: cwd.as_deref(),
        windows: cfg!(windows),
    })?;
    let mcp_arguments = crate::wire::mcp_call::hook_arguments(mapped.action.as_ref(), &call.input);
    let session = p
        .session_context
        .and_then(|s| s.root_session_id)
        .filter(|s| !s.is_empty())
        .or(p.task_id.filter(|s| !s.is_empty()));
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(session),
        call_id: call.id.filter(|id| !id.is_empty()),
        cwd,
        tool: mapped.tool.unwrap_or(name),
        action: mapped.action,
        content: None,
        edits: Vec::new(),
        patch: None,
        mcp_arguments,
        sandboxed: false,
        event: HookEvent::PreToolUse,
    })
}

/// Nothing for `defer` (ADR-025) and `{}` for `allow`: Cline reads neither as
/// a decision and has no "allow" that skips its own approval, so both leave
/// the call to it, as without OpenMoat. Anything else stops the call.
pub(crate) fn render(decision: &Decision) -> String {
    match decision.verdict {
        Verdict::Defer => String::new(),
        Verdict::Allow => "{}".to_owned(),
        // `Deny`, a `review` (which `Host::answer` has already made a deny) and
        // any verdict added to the core later stop the call.
        _ => serde_json::json!({
            "cancel": true,
            "errorMessage": crate::reason_line(decision),
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests;
