//! Anthropic's Claude Code: `PreToolUse` ([`crate::wire::pre_tool_use`]),
//! `ConfigChange` ([`config_change`]), `SessionStart` ([`session_start`]) and
//! `PostToolUse` ([`post_tool_use`]).

use openmoat_core::Decision;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    Bundle, Reviews, CONFIG_HOOK_TIMEOUT_S, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, McpFile,
    McpSpec, McpServersJson, Prefixed, ProjectSettingsSpec, ProxySessions, SandboxFormat, SandboxSpec, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) mod config_change;
mod advisories;
mod doc;
mod from_cursor;
mod ide_tools;
mod mcp;
mod post_tool_use;
pub(crate) mod project_settings;
mod session_start;
mod settings;

/// Every Claude Code tool `openmoat-hosts` maps to an action; a tool missing here
/// never reaches `moat guard`.
/// `Skill` and `EnterWorktree` without a `path` are recorded and left to Claude
/// Code's own permission flow; changing this list makes existing entries stale,
/// which `moat doctor` and `moat status` report with "run `moat init`".
const TOOL_MATCHER: &str = "Bash|Monitor|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Glob|Grep|LSP|SendFile|WebFetch|WebSearch|ReadMcpResourceTool|EnterWorktree|Skill|Artifact|ArtifactData|mcp__.*";

/// The tools whose output may be content an attacker controls (ADR-057): a
/// shell command (`gh issue view`, `curl`), a fetch, a search, an MCP result.
/// The guard keeps fingerprints of it only when the call reads from outside
/// (`CompiledPolicy::output_source`).
const OUTPUT_MATCHER: &str = "Bash|WebFetch|WebSearch|ReadMcpResourceTool|mcp__.*";

/// `PreToolUse` asks Claude Code to block a call whose hook fails
/// (`onFailure`); the settings-change veto does not, and a session start
/// cannot be blocked. `SessionStart` gives each session its own credential for
/// `openmoat proxy` (ADR-044) at every start, resume, `/clear` and compaction.
/// `PostToolUse` reports what a call returned, after it ran, so it has
/// nothing to block (ADR-057).
const HOOKS: &[HookSpec] = &[
    HookSpec::new("PreToolUse", TOOL_MATCHER, TOOL_HOOK_TIMEOUT_S, true),
    HookSpec::new(
        "ConfigChange",
        "user_settings|project_settings|local_settings",
        CONFIG_HOOK_TIMEOUT_S,
        false,
    ),
    HookSpec::new(
        session_start::EVENT,
        "startup|resume|clear|compact",
        CONFIG_HOOK_TIMEOUT_S,
        false,
    ),
    HookSpec::new(post_tool_use::EVENT, OUTPUT_MATCHER, CONFIG_HOOK_TIMEOUT_S, false),
];

/// Claude Code prompts on `PreToolUse`, except in a permission mode that puts no
/// question to a person (`bypassPermissions`, `dontAsk`).
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "claude-code",
    display_name: "Claude Code",
    reviews: Reviews {
        on_pre_tool_use: None,
        on_no_prompt: Some("Claude Code's permission mode does not prompt"),
        defer_is_review_on_no_prompt: false,
        allow_last_hint: true,
        // `bypassPermissions` skips its prompts and `dontAsk` denies whatever
        // would prompt.
        prompt_free_modes: &["bypassPermissions", "dontAsk"],
        ..Reviews::BASE
    },
    resume_hint: Some("`claude --continue` resumes this one"),
    on_hook_failure: "before 2.1.295 runs the call when the hook is missing, cannot start, \
         exits non-zero other than 2, or times out (default 600 s); from 2.1.295 blocks it \
         (`openmoat init` sets `onFailure: \"block\"`); on Windows without Git for Windows \
         or Git Bash, before 2.1.310 a hook's block, its exit 2 included, can still let \
         the call through",
    // "Block the action when a hook fails" and "Non-blocking error" in the
    // hooks reference: a failure or a timeout lets the call go ahead unless
    // the entry sets `onFailure: "block"` (v2.1.295 or later).
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::BlocksFrom((2, 1, 295)),
        times_out: crate::FailureOutcome::BlocksFrom((2, 1, 295)),
        timeout_s: Some(600),
        turned_off_by: "`disableAllHooks: true` in a settings file (a project's included), \
                        `--settings '{\"disableAllHooks\": true}'`, or deleting the entry",
        sources: &["https://code.claude.com/docs/en/hooks"],
    },
    gaps: "file tools, WebFetch and MCP servers run outside the OS sandbox; before Claude \
         Code 2.1.295 calls run unchecked if the hook binary is missing or crashes",
    install: Some(InstallSpec {
        dir_variable: "CLAUDE_CONFIG_DIR",
        dir_name: ".claude",
        config_file: "settings.json",
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&crate::wire::hook_file::nested::Nested),
        relaxed_keys: settings::RELAXED_KEYS,
        relaxed_check: crate::RelaxedCheck::ByKey,
        unpinned_keys: settings::UNPINNED_KEYS,
        ..InstallSpec::BASE
    }),
    mcp: Some(McpSpec {
        user_file: McpFile::BesideDefaultDir(".claude.json"),
        user_reader: &mcp::ClaudeJson,
        project_files: &[(".mcp.json", &McpServersJson)],
        tool_names: &Prefixed,
        auto_start: Some(&mcp::AutoStartSettings),
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
        windows_modes: None,
        tiocsti_open_on_linux: false,
        // The hooks reference, "Persist environment variables": each Bash
        // command runs the file's lines first (ADR-044).
        proxy_sessions: ProxySessions::EnvFile("CLAUDE_ENV_FILE"),
    }),
    // Merged over the user `settings.json`, where a key set wins
    // (`disableAllHooks`, `hooks`, `env`, …).
    project_settings: Some(ProjectSettingsSpec {
        dir: ".claude",
        shared: "settings.json",
        local: Some("settings.local.json"),
        more: &[],
        hook_dir: None,
        plugin_dir: None,
        reader: &project_settings::READER,
        user_file: "settings.json",
        user_more: &[],
    }),
    // `claude`, or `node` running a versioned file (`claude/versions/2.1.0`)
    // or the npm package's `cli.js`.
    process: crate::contract::ProcessSpec {
        names: &["claude"],
        package_dirs: &[&["claude", "versions"], &["claude-code"]],
        helper: None,
    },
    // `kernel-self`'s lines for Claude Code stay hand-written among Codex's
    // and Cursor's.
    protect: crate::contract::Protect {
        taint: &[crate::contract::Paths::new(
            "Claude Code: the memory file it loads into every session, its directory\n\
             (settings, hooks, skills, agents, memory) and a project's, the person's MCP\n\
             servers and a project's",
            &["**/CLAUDE.md", "**/.claude/**", "**/.claude.json", "**/.mcp.json"],
        )],
        temp_dirs: &[crate::contract::Paths::new(
            "Claude Code: the output of its background commands, which it reads back\n\
             with `cat` (`/tmp/claude-<uid>/`)",
            &["/tmp/claude-*/**", "/private/tmp/claude-*/**"],
        )],
        credentials: &[crate::contract::Paths::new(
            "Claude Code: its login where it keeps it in a file (Linux and Windows, and\n\
             macOS when the Keychain refuses it) and the Anthropic profiles `ant auth\n\
             login` writes (docs: Authentication, Credential management)",
            &["~/.claude/.credentials.json", "~/.config/anthropic/**"],
        )],
        runs_later: &[
            crate::contract::RunsLater::agent_config(
                "Claude Code: a project's hook scripts and MCP servers, and its subagents,\n\
                 skills and slash commands, which carry their own hooks, allowed tools and shell",
                &[
                    "**/.claude/hooks/**",
                    "**/.mcp.json",
                    "**/.claude/agents/**",
                    "**/.claude/skills/**",
                    "**/.claude/commands/**",
                ],
            ),
            crate::contract::RunsLater::review(
                "Claude Code: the person's MCP servers and plugins",
                &["~/.claude.json", "~/.claude/plugins/**"],
            ),
        ],
        ..crate::contract::Protect::BASE
    },
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    bundled: BUNDLED,
    // Managed settings (<https://code.claude.com/docs/en/settings>, "Settings
    // files"): an administrator's `managed-settings.json` and the drop-ins in
    // `managed-settings.d/` beside it outrank every other file;
    // `disableAllHooks` there turns every hook off, and
    // `allowManagedHooksOnly` runs only the hooks they list.
    system_settings: Some(crate::contract::SystemSettingsSpec {
        files: &[
            crate::contract::SystemFile::at(
                "/Library/Application Support/ClaudeCode/managed-settings.json",
                &[crate::contract::Platform::MacOs],
            ),
            crate::contract::SystemFile::at(
                "/etc/claude-code/managed-settings.json",
                &[crate::contract::Platform::Linux, crate::contract::Platform::Wsl],
            ),
            crate::contract::SystemFile::at(
                "C:/Program Files/ClaudeCode/managed-settings.json",
                &[crate::contract::Platform::Windows],
            ),
        ],
        drop_ins: Some("managed-settings.d"),
        managed_only: Some("allowManagedHooksOnly"),
        hooks_key: "hooks",
    }),
    // The Bash tool's shell; hooks run under `sh -c` or exec form. A value that
    // is not a working bash or zsh is ignored without a word (ADR-075).
    tool_token: crate::ToolToken::Wrapper {
        vars: &["CLAUDE_CODE_SHELL", "SHELL"],
        on_path: false,
    },
    run_env: &[
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ],
    // Claude in Chrome, which Claude Code provides itself (`claude --chrome`,
    // the browser extension), not a server an MCP configuration file defines.
    // Every tool that returns what a page says (`get_page_text`, `read_page`,
    // `find`, `navigate`, `javascript_tool`, the console and network logs,
    // screenshots) is left out (ADR-057 amendment of 2026-11-07).
    builtin_mcp: Some(crate::contract::BuiltinMcp {
        server: "claude-in-chrome",
        why: "Claude Code: Claude in Chrome's tab, window, browser and shortcut lists (tab ids,\n\
              titles, URLs), the browser's own bookkeeping",
        metadata_tools: &[
            "list_connected_browsers",
            "resize_window",
            "select_browser",
            "shortcuts_list",
            "switch_browser",
            "tabs_close_mcp",
            "tabs_context_mcp",
            "tabs_create_mcp",
        ],
    }),
    ..HostSpec::BASE
};

/// The Claude Code extension for VS Code bundles its own Claude Code for its
/// chat panel and puts no `claude` on the search path; its version is the
/// version of the Claude Code it bundles (<https://code.claude.com/docs/en/vs-code>).
/// The same extension installs into VS Code's forks, each with its own
/// extensions folder. The JetBrains plugin bundles none: it runs the `claude`
/// on the search path, or the command its settings name
/// (<https://code.claude.com/docs/en/jetbrains>).
const BUNDLED: &[Bundle] = &[
    Bundle::new("VS Code", &[".vscode", "extensions"], EXTENSION),
    Bundle::new("VS Code Insiders", &[".vscode-insiders", "extensions"], EXTENSION),
    // A remote host's VS Code Server, where the extension runs over SSH,
    // in a container or in WSL.
    Bundle::new("VS Code Server", &[".vscode-server", "extensions"], EXTENSION),
    Bundle::new("Cursor", &[".cursor", "extensions"], EXTENSION),
    Bundle::new("Windsurf", &[".windsurf", "extensions"], EXTENSION),
    Bundle::new("VSCodium", &[".vscode-oss", "extensions"], EXTENSION),
];

/// The Claude Code extension's identifier on the VS Code Marketplace.
const EXTENSION: &str = "anthropic.claude-code";

/// Claude Code's format, also sent by the Continue CLI.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// `PreToolUse` may come without its event name. Cursor runs this hook
    /// too, with its own input ([`from_cursor`]).
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        if from_cursor::sent_by_cursor(payload) {
            return from_cursor::parse(event, payload);
        }
        match event {
            None | Some(pre_tool_use::EVENT) => {
                pre_tool_use::parse_with(host, payload, ide_tools::action)
            }
            Some(config_change::EVENT) => config_change::parse(host, payload),
            Some(session_start::EVENT) => session_start::parse(host, payload),
            Some(post_tool_use::EVENT) => post_tool_use::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn event_of(&self, event: &str) -> HookEvent {
        match event {
            config_change::EVENT => HookEvent::ConfigChange {
                source: String::new(),
                change_type: None,
            },
            // Cursor's name for it, when Cursor runs this hook (`from_cursor`).
            session_start::EVENT | "sessionStart" => HookEvent::SessionStart {
                source: String::new(),
            },
            // Cursor's name for it too, when Cursor runs this hook (`from_cursor`).
            post_tool_use::EVENT | "postToolUse" => HookEvent::PostToolUse {
                output: String::new(),
            },

            "preToolUse" => HookEvent::PreToolUseNoPrompt,
            _ => HookEvent::PreToolUse,
        }
    }

    fn render(&self, event: &HookEvent, decision: &Decision) -> String {
        match event {
            HookEvent::PreToolUse | HookEvent::PreToolUseNoPrompt => pre_tool_use::render(decision),
            HookEvent::ConfigChange { .. } => config_change::render(decision),
            HookEvent::SessionStart { .. } => session_start::render(decision),
            HookEvent::PostToolUse { .. } => post_tool_use::render(decision),
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
