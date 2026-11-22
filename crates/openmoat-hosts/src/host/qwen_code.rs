//! Qwen Code (`qwen`, npm `@qwen-code/qwen-code`): the `PreToolUse` command
//! hook in `~/.qwen/settings.json`.
//!
//! Hook docs: <https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/>
//! (updated 2026-11-11), read 2026-11-14 with the source of
//! `QwenLM/qwen-code` `main` (`packages/core/src/hooks/hookRunner.ts`,
//! `hookEventHandler.ts`, `hook-matcher.ts`, `core/toolHookTriggers.ts`,
//! `tools/tool-names.ts`, `config/storage.ts`); npm's latest release was
//! 0.27.3. Nothing here was checked against a running `qwen`.
//!
//! Input is Claude Code's `PreToolUse` document (`session_id`,
//! `transcript_path`, `cwd`, `hook_event_name`, `permission_mode`,
//! `tool_name`, `tool_input`, `tool_use_id`) with Qwen Code's own tool names
//! (`run_shell_command`, `read_file`, …; MCP tools `mcp__<server>__<tool>`).
//! Output is Claude Code's too: `hookSpecificOutput.permissionDecision`
//! `allow`, `deny` or `ask`, which pauses for the person in the terminal
//! whatever the approval mode (YOLO included) and is a deny in a headless
//! run; nothing on stdout leaves the call to Qwen Code's own permission flow.
//! Exit 2 blocks with stderr as the reason.
//!
//! Qwen Code has no fail-closed setting: a hook that times out, cannot start,
//! is killed, exits non-zero other than 2 without JSON, or prints JSON it
//! cannot parse is a non-blocking error and the call runs
//! (`toolHookTriggers.ts`: "Hook errors should not block tool execution").

use openmoat_core::Decision;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    HookLayout, HookSpec, HookVersions, HostAdapter, HostSpec, InstallSpec, McpFile, McpServersJson,
    McpSpec, Prefixed, ProjectSettingsSpec, Reviews, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, Writes, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

mod doc;
mod hook_file;
mod hook_off;
mod project_settings;
mod protect;
mod tools;
mod weekly;

/// `*` matches every tool (`hook-matcher.ts`); a regular expression would
/// not reach the Claude Code names Qwen Code also accepts. 600 s is read as
/// seconds: Qwen Code takes a value of 1000 or more as milliseconds.
const HOOKS: &[HookSpec] = &[HookSpec::new(
    pre_tool_use::EVENT,
    "*",
    TOOL_HOOK_TIMEOUT_S,
    false,
)];

/// `PreToolUse` came with Qwen Code 0.13.0 (QwenLM/qwen-code#2203, in that
/// release's notes).
const VERSIONS: HookVersions = HookVersions {
    program: "qwen",
    oldest: (0, 13, 0),
    older: "Qwen Code before 0.13.0 runs no `PreToolUse` hook; upgrade Qwen Code",
    hooks: &[((0, 13, 0), "Qwen Code's `PreToolUse`")],
};

/// The tools whose arguments write a file (`write-file.ts`, `edit.ts`).
const WRITES: Writes = Writes {
    whole: &["write_file"],
    edit: &["edit"],
    multi_edit: &[],
};

/// Qwen Code puts a `review` (`ask`) to the person itself.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "qwen-code",
    display_name: "Qwen Code",
    reviews: Reviews {
        on_pre_tool_use: None,
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, crashes, exits \
         non-zero other than 2 without a decision, prints JSON it cannot read, or times out \
         (600 s as `openmoat init` writes it); Qwen Code has no setting that blocks a failed \
         hook",
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::Runs,
        times_out: crate::FailureOutcome::Runs,
        timeout_s: Some(600),
        turned_off_by: "`disableAllHooks: true` in a settings file (whether a project's turns \
                        the person's hooks off was not verified, so OpenMoat assumes it does), \
                        `--safe-mode`, `--bare`, or deleting the entry",
        sources: &[
            "https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/",
            "https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/hooks/hookRunner.ts",
            "https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/core/toolHookTriggers.ts",
        ],
    },
    gaps: "preview: built from Qwen Code's documentation and source, not yet run against a \
         real `qwen`; no OS sandbox from OpenMoat (Qwen Code's own `--sandbox` is the \
         person's to turn on); a hook that fails or times out lets the call run; a \
         project's `.qwen/settings.json` may turn hooks off (`disableAllHooks`) or add a \
         hook that rewrites a call's arguments (`updatedInput`), once the person approves \
         it or trusts the folder (`openmoat status` and `doctor` warn about one); \
         extension hooks run beside OpenMoat's; `--safe-mode` and `--bare` run no hooks; a \
         change Qwen Code makes to `settings.json` itself (a model or theme) is drift until \
         `openmoat init` or `openmoat doctor --accept`; on Windows the entry runs through \
         PowerShell, which was not tried",
    limit: Some(
        "Qwen Code is a preview host: no real `qwen` has run OpenMoat's hook yet, and a hook \
         that fails lets the call run",
    ),
    // `QWEN_HOME` names the directory itself, else `~/.qwen`
    // (`packages/core/src/config/storage.ts`).
    install: Some(InstallSpec {
        dir_variable: "QWEN_HOME",
        dir_name: ".qwen",
        config_file: "settings.json",
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&hook_file::Qwen),
        versions: Some(VERSIONS),
        // Each session is recorded as `projects/<project>/chats/<session id>.jsonl`,
        // which `--resume` reads back, from 0.13.0 (the first release with
        // `PreToolUse`) on: `ensureConversationFile` in
        // https://github.com/QwenLM/qwen-code/blob/v0.13.0/packages/core/src/services/chatRecordingService.ts
        // and `getProjectDir` in `config/storage.ts`. `QWEN_RUNTIME_DIR` moves
        // `projects/` out of the configuration directory: fewer warnings there.
        liveness: Some(crate::Liveness {
            settings: &[],
            sessions: crate::Sessions::Known(&[crate::Activity::new(&[
                "projects",
                crate::Activity::ANY,
                "chats",
            ])
            .ending(".jsonl")]),
        }),
        ..InstallSpec::BASE
    }),
    // `mcpServers` in the user and the project `settings.json` (the settings
    // reference); a tool is `mcp__<server>__<tool>` (`tools/mcp-tool.ts`).
    mcp: Some(McpSpec {
        user_file: McpFile::HookFile,
        user_reader: &McpServersJson,
        project_files: &[(".qwen/settings.json", &McpServersJson)],
        tool_names: &Prefixed,
        call_ids: None,
        auto_start: None,
    }),
    // A project's `.qwen/settings.json` is merged over the person's, and its
    // hooks run once the person approves them or trusts the folder.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".qwen",
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
    docs: doc::DOCS,
    // System settings outrank the person's and a project's, and system
    // defaults sit under them; each has a variable that moves it (the
    // settings reference, "Settings files").
    system_settings: Some(crate::contract::SystemSettingsSpec {
        files: protect::SYSTEM_FILES,
        drop_ins: None,
        managed_only: None,
        hooks_key: "hooks",
    }),
    tool_token: crate::ToolToken::NotWithheld {
        why: "how Qwen Code starts tool commands and hooks was not checked",
    },
    // Outside the project Qwen Code writes its own directory alone: settings,
    // its sign-in, chat recordings, `file-history/` for `/rewind` and its
    // locales are all under `~/.qwen` (`QWEN_HOME`), by the settings reference
    // (`docs/users/configuration/settings.md`); the system files under
    // `/etc/qwen-code` are only read (ADR-108).
    run: crate::RunFacts::Known {
        program: "qwen",
        args: &[],
        writes: &[crate::RunWrite::ConfigDir],
    },
    weekly: weekly::WEEKLY,
    hook_off: hook_off::HOOK_OFF,
    plugin: crate::contract::Plugin::None {
        why: "Qwen Code's extensions (`qwen extensions install`) can carry hooks, but which \
              manifest field holds them was not verified; `openmoat init` writes the hook into \
              `settings.json`",
    },
    ..HostSpec::BASE
};

/// Qwen Code's `PreToolUse` hook.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// `PreToolUse`, which names itself in `hook_event_name`.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None | Some(pre_tool_use::EVENT) => {
                pre_tool_use::parse_writing(host, payload, tools::action, &WRITES)
            }
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        pre_tool_use::render(decision)
    }

    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        let (tool, input) = match call {
            Call::Shell(_) if tools::POWERSHELL => return None,
            Call::Shell(command) => (
                "run_shell_command".to_owned(),
                json!({ "command": command, "is_background": false }),
            ),
            Call::Read(path) => ("read_file".to_owned(), json!({ "file_path": at.file(path) })),
            Call::Write(path) => (
                "write_file".to_owned(),
                json!({ "file_path": at.file(path), "content": CONTENT }),
            ),
            Call::Edit(path) => (
                "edit".to_owned(),
                json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
            ),
            Call::Fetch(url) => (
                "web_fetch".to_owned(),
                json!({ "url": url, "prompt": "summarise" }),
            ),
            Call::Mcp { server, tool, args } => (format!("mcp__{server}__{tool}"), args.clone()),
        };
        Some(bench::payload(&tool, &input, at))
    }

    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit, true)
    }
}

#[cfg(test)]
mod tests;
