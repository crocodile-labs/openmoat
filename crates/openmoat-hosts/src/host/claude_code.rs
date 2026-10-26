//! Anthropic's Claude Code: `PreToolUse` ([`crate::wire::pre_tool_use`]) and
//! `ConfigChange` ([`config_change`]).

use openmoat_core::Decision;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    Asks, CONFIG_HOOK_TIMEOUT_S, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile,
    McpSpec, McpServersJson, Prefixed, ProjectSettingsSpec, SandboxFormat, SandboxSpec, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) mod config_change;
mod advisories;
mod doc;
mod mcp;
pub(crate) mod project_settings;

/// Every Claude Code tool `openmoat-hosts` maps to an action; a tool missing here
/// never reaches `moat guard`.
/// `Skill` and `EnterWorktree` without a `path` are recorded and left to Claude
/// Code's own permission flow; changing this list makes existing entries stale,
/// which `moat doctor` and `moat status` report with "run `moat init`".
const TOOL_MATCHER: &str = "Bash|Monitor|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Glob|Grep|LSP|SendFile|WebFetch|WebSearch|ReadMcpResourceTool|EnterWorktree|Skill|Artifact|ArtifactData|mcp__.*";

/// `PreToolUse` asks Claude Code to block a call whose hook fails
/// (`onFailure`); the settings-change veto does not.
const HOOKS: &[HookSpec] = &[
    HookSpec::new("PreToolUse", TOOL_MATCHER, TOOL_HOOK_TIMEOUT_S, true),
    HookSpec::new(
        "ConfigChange",
        "user_settings|project_settings|local_settings",
        CONFIG_HOOK_TIMEOUT_S,
        false,
    ),
];

/// Claude Code asks on `PreToolUse`, except in a permission mode that puts no
/// question to a person (`bypassPermissions`, `dontAsk`).
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "claude-code",
    display_name: "Claude Code",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Claude Code's permission mode does not ask"),
        defer_is_ask_on_no_ask: false,
        allow_last_hint: true,
        // `bypassPermissions` skips its prompts and `dontAsk` denies whatever
        // would prompt.
        prompt_free_modes: &["bypassPermissions", "dontAsk"],
        ..Asks::BASE
    },
    resume_hint: Some("`claude --continue` resumes this one"),
    on_hook_failure: "before 2.1.295 runs the call when the hook is missing, cannot start, \
         exits non-zero other than 2, or times out (default 600 s); from 2.1.295 blocks it \
         (`openmoat init` sets `onFailure: \"block\"`)",
    gaps: "file tools, WebFetch and MCP servers run outside the OS sandbox; before Claude \
         Code 2.1.295 calls run unchecked if the hook binary is missing or crashes",
    install: Some(InstallSpec {
        dir_variable: "CLAUDE_CONFIG_DIR",
        dir_name: ".claude",
        config_file: "settings.json",
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&crate::wire::hook_file::nested::Nested),
        // Claude Code's list, with its permission lists, is the CLI's
        // (`integrity/relaxed.rs`).
        relaxed_keys: &[],
        ..InstallSpec::BASE
    }),
    mcp: Some(McpSpec {
        user_file: McpFile::BesideDefaultDir(".claude.json"),
        user_reader: &mcp::ClaudeJson,
        project_files: &[(".mcp.json", &McpServersJson)],
        tool_names: &Prefixed,
    }),
    // Claude Code's sandbox runs on macOS, Linux and WSL2 only, and with
    // `failIfUnavailable` Claude Code exits at startup where it cannot run:
    // native Windows (#327).
    sandbox: Some(SandboxSpec {
        format: SandboxFormat::ClaudeSettings,
        file: "settings.json",
        unavailable_on_windows: Some(
            "sandbox not available on native Windows; the hook still applies the policy \
             (use WSL2 for OS confinement)",
        ),
        tiocsti_open_on_linux: false,
    }),
    // Merged over the user `settings.json`, where a key set wins
    // (`disableAllHooks`, `hooks`, `env`, …).
    project_settings: Some(ProjectSettingsSpec {
        dir: ".claude",
        shared: "settings.json",
        local: Some("settings.local.json"),
        more: &[],
        hook_dir: None,
        reader: &project_settings::READER,
        user_file: "settings.json",
    }),
    // `claude`, or `node` running a versioned file (`claude/versions/2.1.0`)
    // or the npm package's `cli.js`.
    process: crate::contract::ProcessSpec {
        names: &["claude"],
        package_dirs: &[&["claude", "versions"], &["claude-code"]],
        helper: None,
    },
    // `kernel-self`'s and the taint list's lines for Claude Code stay
    // hand-written among Codex's and Cursor's.
    protect: crate::contract::Protect {
        credentials: &[crate::contract::Paths::new(
            "Claude Code: its login where it keeps it in a file (Linux and Windows, and\n\
             macOS when the Keychain refuses it) and the Anthropic profiles `ant auth\n\
             login` writes (docs: Authentication, Credential management)",
            &["~/.claude/.credentials.json", "~/.config/anthropic/**"],
        )],
        ..crate::contract::Protect::BASE
    },
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// Claude Code's format, also sent by the Continue CLI.
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
            Some(config_change::EVENT) => config_change::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn event_of(&self, event: &str) -> HookEvent {
        if event == config_change::EVENT {
            HookEvent::ConfigChange {
                source: String::new(),
                change_type: None,
            }
        } else {
            HookEvent::PreToolUse
        }
    }

    fn render(&self, event: &HookEvent, decision: &Decision) -> String {
        match event {
            HookEvent::PreToolUse | HookEvent::PreToolUseNoAsk => pre_tool_use::render(decision),
            HookEvent::ConfigChange { .. } => config_change::render(decision),
        }
    }

    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        let (tool, input) = match call {
            Call::Read(path) => ("Read".to_owned(), json!({ "file_path": at.file(path) })),
            Call::Write(path) => (
                "Write".to_owned(),
                json!({ "file_path": at.file(path), "content": CONTENT }),
            ),
            Call::Edit(path) => (
                "Edit".to_owned(),
                json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
            ),
            Call::Fetch(url) => (
                "WebFetch".to_owned(),
                json!({ "url": url, "prompt": "summarise" }),
            ),
            other => bench::common_tool(other)?,
        };
        Some(bench::payload(&tool, &input, at))
    }

    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit, true)
    }
}
