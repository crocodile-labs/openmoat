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
    Reviews, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile, McpSpec, McpServersJson, Prefixed,
    ProjectSettingsSpec, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError};

mod advisories;
mod bench;
mod doc;
pub(crate) mod hook_file;
mod project_settings;
mod protect;
mod settings;
mod tools;

/// The one event OpenMoat answers.
pub(crate) const EVENT: &str = "BeforeTool";

/// `*` matches every tool name, MCP tools included (`hookPlanner.js`
/// `matchesContext`). Gemini CLI takes the timeout in milliseconds; the
/// installer converts ([`hook_file::Gemini`]).
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "*", TOOL_HOOK_TIMEOUT_S, false)];

/// Gemini CLI puts a `review` to the person itself.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "gemini-cli",
    display_name: "Gemini CLI",
    reviews: Reviews {
        on_pre_tool_use: None,
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "runs the call when the hook times out, is killed by a signal or exits 1 \
         (Gemini CLI has no fail-closed setting); blocks it when the hook exits 2, or exits \
         with any other code and prints something, as a missing `openmoat` does",
    // Exit 1, a signal or a timeout is a warning and the call runs; another
    // non-zero exit with output blocks (a missing `openmoat` prints one), a
    // silent crash does not. Gemini CLI has no fail-closed setting.
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::Runs,
        times_out: crate::FailureOutcome::Runs,
        timeout_s: Some(600),
        turned_off_by: "`hooks` turned off in the user's or a project's `settings.json`, or a \
                        folder Gemini CLI does not trust (which runs no settings hooks)",
        sources: &["https://geminicli.com/docs/hooks/reference/"],
    },
    gaps: "no OS sandbox from OpenMoat; in a folder Gemini CLI does not trust it runs no \
         settings hooks at all and asks the person before every tool instead; a project's \
         `.gemini/settings.json` can turn hooks off or add a hook that rewrites a call's \
         arguments (`openmoat status` and `doctor` warn about one); extension hooks run beside \
         OpenMoat's; a search without a `dir_path` is checked over the working directory and \
         the `context.includeDirectories` of the user and project settings, not over \
         directories added with `--include-directories` or `/directory add`; a hook that \
         times out lets the call run",
    // `GEMINI_CLI_HOME` replaces the home directory `.gemini` is looked up in
    // (`homedir()` in `packages/core/src/utils/paths.ts`).
    install: Some(InstallSpec {
        dir_variable: "GEMINI_CLI_HOME",
        dir_name: ".gemini",
        config_file: "settings.json",
        hooks: HOOKS,
        dir_variable_is_home: true,
        hook_file: HookLayout::Entries(&hook_file::Gemini),
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
        auto_start: None,
    }),
    // A trusted folder's `.gemini/settings.json` is merged over the user's:
    // `hooksConfig.disabled` lists are joined, and its `BeforeTool` hooks run
    // beside OpenMoat's and may rewrite a call's arguments (`docs/hooks/`,
    // `config/settingsSchema.ts`, 0.65.0). There is no local file.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".gemini",
        shared: "settings.json",
        local: None,
        more: &[],
        hook_dir: None,
        plugin_dir: None,
        reader: &project_settings::READER,
        user_file: "settings.json",
        user_more: &[],
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    workspace_dirs: Some(settings::include_directories),
    // System settings outrank the person's own, and system defaults sit
    // under them; each has a variable that moves it
    // (`packages/cli/src/config/settings.ts`). `hooksConfig` there turns
    // hooks off as in the person's file.
    system_settings: Some(crate::contract::SystemSettingsSpec {
        files: &[
            crate::contract::SystemFile::at(
                "/Library/Application Support/GeminiCli/settings.json",
                &[crate::contract::Platform::MacOs],
            )
            .moved_by("GEMINI_CLI_SYSTEM_SETTINGS_PATH"),
            crate::contract::SystemFile::at(
                "/Library/Application Support/GeminiCli/system-defaults.json",
                &[crate::contract::Platform::MacOs],
            )
            .moved_by("GEMINI_CLI_SYSTEM_DEFAULTS_PATH"),
            crate::contract::SystemFile::at(
                "/etc/gemini-cli/settings.json",
                &[crate::contract::Platform::Linux, crate::contract::Platform::Wsl],
            )
            .moved_by("GEMINI_CLI_SYSTEM_SETTINGS_PATH"),
            crate::contract::SystemFile::at(
                "/etc/gemini-cli/system-defaults.json",
                &[crate::contract::Platform::Linux, crate::contract::Platform::Wsl],
            )
            .moved_by("GEMINI_CLI_SYSTEM_DEFAULTS_PATH"),
            crate::contract::SystemFile::at(
                "C:/ProgramData/gemini-cli/settings.json",
                &[crate::contract::Platform::Windows],
            )
            .moved_by("GEMINI_CLI_SYSTEM_SETTINGS_PATH"),
            crate::contract::SystemFile::at(
                "C:/ProgramData/gemini-cli/system-defaults.json",
                &[crate::contract::Platform::Windows],
            )
            .moved_by("GEMINI_CLI_SYSTEM_DEFAULTS_PATH"),
        ],
        drop_ins: None,
        managed_only: None,
        hooks_key: "hooks",
    }),
    tool_token: crate::ToolToken::NotWithheld {
        why: "Gemini CLI starts tool commands and hooks the same way, with `bash` from `PATH`",
    },
    // `.gemini` of its configuration reference (ADR-076).
    run: crate::RunFacts::Known {
        program: "gemini",
        args: &[],
        writes: &[crate::RunWrite::ConfigDir],
    },
    run_env: &[
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
    ],
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
    let mcp_arguments = crate::wire::mcp_call::hook_arguments(mapped.action.as_ref(), &p.tool_input);
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: None,
        cwd,
        tool: mapped.tool.unwrap_or(p.tool_name),
        action: mapped.action,
        content,
        edits: Vec::new(),
        patch: None,
        mcp_arguments,
        sandboxed: false,
        event: HookEvent::PreToolUse,
    })
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025): no output, so Gemini CLI's own policy decides, as
    // without OpenMoat. `allow` changes nothing there either: Gemini CLI reads
    // only `deny` (or `block`) and `"ask"` from a `BeforeTool` hook.
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    let line = crate::reason_line(decision);
    // OpenMoat's `review` is sent as the host's "ask" (`host_verdict`).
    let mut reply = serde_json::json!({ "decision": crate::wire::host_verdict(decision.verdict) });
    // `reason` goes to the model with a deny; `systemMessage` is shown to the
    // person, beside the confirmation for a `review`.
    if decision.verdict != Verdict::Allow {
        reply["reason"] = Value::from(line.as_str());
        reply["systemMessage"] = Value::from(line);
    }
    reply.to_string()
}

#[cfg(test)]
mod tests;
