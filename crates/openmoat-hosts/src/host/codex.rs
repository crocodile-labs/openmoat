//! The Codex CLI: `PreToolUse` in Claude Code's format
//! ([`crate::wire::pre_tool_use`]).

use openmoat_core::{Decision, Verdict};
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    Asks, HookFormat, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile, McpLayout, McpSpec,
    McpToolNames, ProjectSettingsSpec, SandboxFormat, SandboxSpec, SettingsFormat,
    TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

/// Codex runs `PreToolUse` for shell, `apply_patch` file edits and MCP tools;
/// web search and hosted tools have no hook. Codex has no key that blocks a
/// call whose hook fails: "a failed `PreToolUse` hook marks that hook run as
/// failed, reports the error, and continues the tool call"
/// (<https://learn.chatgpt.com/docs/hooks>), so `guard` itself must answer.
const HOOKS: &[HookSpec] = &[HookSpec::new(
    "PreToolUse",
    "Bash|apply_patch|mcp__.*",
    TOOL_HOOK_TIMEOUT_S,
    false,
)];

/// Codex's `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and
/// then runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: Some("Codex hooks cannot ask"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, exits non-zero \
         other than 2 (or 2 with nothing on stderr), or times out (default 600 s)",
    gaps: "web search and hosted tools are not hooked; asks become denies; Codex skips a \
         new or changed hook until the person trusts it in `/hooks`, and `[features] hooks = \
         false` turns hooks off (`openmoat status` and `doctor` report that); calls run \
         unchecked if the hook binary is missing or crashes",
    install: Some(InstallSpec {
        dir_variable: "CODEX_HOME",
        dir_name: ".codex",
        config_file: "hooks.json",
        hooks: HOOKS,
        hook_format: HookFormat::Nested,
        relaxed_keys: &[],
        // Codex runs a new or changed user hook only once the person trusts it
        // in `/hooks` (Codex's hooks documentation).
        trust_step: Some(
            "open Codex and trust OpenMoat's hook in /hooks; Codex runs a changed hook only then",
        ),
    }),
    mcp: Some(McpSpec {
        user_file: McpFile::BesideHookFile("config.toml"),
        user_layout: McpLayout::Toml,
        project_files: &[(".codex/config.toml", McpLayout::Toml)],
        tool_names: McpToolNames::Prefixed,
    }),
    sandbox: Some(SandboxSpec {
        format: SandboxFormat::CodexProfile,
        file: "config.toml",
        unavailable_on_windows: None,
    }),
    // A trusted project's `.codex/` layer adds its `config.toml` and
    // `hooks.json`, whose hooks run beside OpenMoat's; `[features] hooks =
    // false` in it or in the user's `config.toml` turns every hook off
    // (<https://learn.chatgpt.com/docs/hooks>).
    project_settings: Some(ProjectSettingsSpec {
        dir: ".codex",
        shared: "config.toml",
        local: Some("hooks.json"),
        hook_dir: None,
        format: SettingsFormat::Codex,
        user_file: "config.toml",
    }),
};

/// Codex sends only `PreToolUse`.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// `PreToolUse` may come without its event name.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None | Some(pre_tool_use::EVENT) => pre_tool_use::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        pre_tool_use::render(decision)
    }

    /// Codex reads files through its shell and has no fetch tool; it writes
    /// and edits with `apply_patch`.
    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        let apply = |body: String| ("apply_patch".to_owned(), json!({ "command": body }));
        let (tool, input) = match call {
            Call::Write(path) => apply(format!(
                "*** Begin Patch\n*** Add File: {}\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            )),
            Call::Edit(path) => apply(format!(
                "*** Begin Patch\n*** Update File: {}\n@@\n-old\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            )),
            other => bench::common_tool(other)?,
        };
        Some(bench::payload(&tool, &input, at))
    }

    /// Codex blocks on exit 2 only with a reason on stderr.
    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        if exit.code == Some(2) && exit.stderr.trim().is_empty() {
            return Answer::Error;
        }
        bench::read_reply(exit, false)
    }

    /// Codex cannot ask, so an `ask` has to arrive as a blocking `deny`.
    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        match verdict {
            Verdict::Ask => Answer::Deny,
            other => other.into(),
        }
    }
}
