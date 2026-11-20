//! Charm's Crush (`crush`): the `PreToolUse` command hook in its global
//! `crush.json`.
//!
//! Hook docs: `docs/hooks/README.md` of `charmbracelet/crush`, read
//! 2026-11-14 with the source at `main` (release v0.101.0):
//! `internal/hooks/{config,input,runner}.go`, `internal/agent/hooked_tool.go`,
//! `internal/agent/tools/*.go`, `internal/config/{config,load,hooks}.go`.
//! Nothing here was checked against a running `crush`.
//!
//! Input is Claude Code's `PreToolUse` document without `transcript_path`:
//! `event`, `hook_event_name`, `session_id`, `cwd`, `tool_name`,
//! `tool_input`, `tool_use_id`, with Crush's own tool names (`bash`, `view`,
//! …; MCP tools `mcp_<server>_<tool>`). Output is Claude Code's too:
//! `hookSpecificOutput.permissionDecision` `allow` (which skips Crush's
//! permission prompt) or `deny`; Crush reads `ask` as no decision and has no
//! answer that asks the person, so a `review` reaches it as a deny. Nothing on
//! stdout falls through to Crush's own permission flow, which `--yolo`
//! skips. Exit 2 blocks with stderr as the reason, exit 49 also halts the
//! turn.
//!
//! Crush has no fail-closed setting: a hook that times out, cannot start,
//! exits with any other code without a decision, or prints output it cannot
//! parse is "no opinion" and the call proceeds.

use openmoat_core::{Decision, Verdict};
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    HookLayout, HookSpec, HookVersions, HostAdapter, HostSpec, InstallSpec, Location, McpFile,
    McpSpec, ProjectSettingsSpec, Reviews, SinglePrefixed, TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, Writes, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

mod doc;
mod hook_file;
mod hook_off;
mod location;
mod mcp;
mod project_settings;
mod protect;
mod tools;

/// No matcher: an entry without one runs for every tool
/// (`internal/hooks/config.go`). Crush takes the timeout in seconds.
const HOOKS: &[HookSpec] = &[HookSpec::new(
    pre_tool_use::EVENT,
    "",
    TOOL_HOOK_TIMEOUT_S,
    false,
)];

/// Hooks came with Crush v0.63.0 (its release notes, 2026-04-27).
const VERSIONS: HookVersions = HookVersions {
    program: "crush",
    oldest: (0, 63, 0),
    older: "Crush before 0.63.0 runs no hooks; upgrade Crush",
    hooks: &[((0, 63, 0), "Crush's `PreToolUse`")],
};

/// The tools whose arguments write a file (`write.go`, `edit.go`,
/// `multiedit.go`).
const WRITES: Writes = Writes {
    whole: &["write"],
    edit: &["edit"],
    multi_edit: &["multiedit"],
};

/// Crush cannot put a `review` to the person: `ask` is no decision to it.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "crush",
    display_name: "Crush",
    reviews: Reviews {
        on_pre_tool_use: Some("Crush has no hook answer that asks the person"),
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, crashes, exits \
         non-zero other than 2 or 49 without a decision, prints output it cannot read, or \
         times out (600 s as `openmoat init` writes it); Crush has no setting that blocks a \
         failed hook",
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::Runs,
        times_out: crate::FailureOutcome::Runs,
        timeout_s: Some(600),
        turned_off_by: "deleting the entry: no setting turns hooks off, and the hooks of every \
                        configuration file are appended to one another",
        sources: &[
            "https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md",
            "https://github.com/charmbracelet/crush/blob/main/internal/hooks/runner.go",
        ],
    },
    gaps: "preview: built from Crush's documentation and source, not yet run against a real \
         `crush`; no OS sandbox from OpenMoat; a hook that fails or times out lets the call \
         run; reviews become denies; a call OpenMoat defers runs unasked under `--yolo`; the \
         tool calls of a subagent (`agent`, `agentic_fetch`) fire no hook, so starting one \
         needs review; a project's `crush.json`, `.crush.json` or `.crushrc` can add a hook \
         that rewrites a call's arguments (`updated_input`), and a `.crushrc` is a Bash script \
         Crush runs when it starts, with no trust prompt (`openmoat status` and `doctor` warn \
         about the JSON files); Crush's `crushrc` files are not read by OpenMoat",
    limit: Some(
        "Crush is a preview host: no real `crush` has run OpenMoat's hook yet, and a hook that \
         fails lets the call run",
    ),
    // `$CRUSH_GLOBAL_CONFIG/crush.json`, else `$XDG_CONFIG_HOME/crush/crush.json`,
    // else `~/.config/crush/crush.json` (`internal/config/load.go`).
    install: Some(InstallSpec {
        dir_variable: location::VARIABLE,
        dir_name: location::DIR_NAME,
        config_file: location::CONFIG_FILE,
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&hook_file::Crush),
        location: Location::Custom(&location::LOCATE),
        versions: Some(VERSIONS),
        liveness: Some(crate::Liveness {
            settings: &[],
            sessions: crate::Sessions::Unknown(
                "Crush keeps its sessions in a database in each project's `.crush` directory, \
                 not in its configuration directory",
            ),
        }),
        ..InstallSpec::BASE
    }),
    // `mcp` in each `crush.json` Crush merges (`MCPConfig` in
    // `internal/config/config.go`); a tool is `mcp_<server>_<tool>`
    // (`internal/agent/tools/mcp-tools.go`).
    mcp: Some(McpSpec {
        user_file: McpFile::HookFile,
        user_reader: &mcp::CrushJson,
        project_files: &[
            ("crush.json", &mcp::CrushJson),
            (".crush.json", &mcp::CrushJson),
            (".crush/crush.json", &mcp::CrushJson),
        ],
        tool_names: &SinglePrefixed,
        auto_start: None,
    }),
    // A project's `crush.json`, `.crush.json` and its workspace's
    // `.crush/crush.json`, found from the working directory up to the git
    // root, are merged over the person's (`lookupConfigs`).
    project_settings: Some(ProjectSettingsSpec {
        dir: "",
        shared: "crush.json",
        local: Some(".crush.json"),
        more: &[".crush/crush.json"],
        hook_dir: None,
        plugin_dir: None,
        reader: &project_settings::READER,
        user_file: location::CONFIG_FILE,
        user_more: &[],
    }),
    protect: protect::PROTECT,
    // `.agents/skills` in a project and `~/.agents/skills`, among Crush's skill
    // folders (`internal/config/load.go`).
    conventions: &[crate::contract::AGENT_SKILLS],
    process: protect::PROCESS,
    docs: doc::DOCS,
    // Loaded first; the hooks of every later file are appended to its own.
    system_settings: Some(crate::contract::SystemSettingsSpec {
        files: protect::SYSTEM_FILES,
        drop_ins: None,
        managed_only: None,
        hooks_key: "hooks",
    }),
    tool_token: crate::ToolToken::NotWithheld {
        why: "Crush runs its `bash` tool and its hooks in its own embedded shell; which \
              variables that shell reads was not checked",
    },
    run: crate::RunFacts::Unknown {
        why: "which directories `crush` writes outside the project was not checked",
    },
    weekly: crate::contract::Weekly {
        runs: crate::WeeklyRuns::NotRun(
            "not yet: how the npm package `@charmland/crush` places its binary when the job \
             turns lifecycle scripts off was not checked, and an install from Crush's release \
             archives is not written",
        ),
        env: &[],
    },
    hook_off: hook_off::HOOK_OFF,
    plugin: crate::contract::Plugin::None {
        why: "Crush has no plugin channel: Agent Skills are its only extensions, and a skill \
              carries no hook",
    },
    ..HostSpec::BASE
};

/// Crush's `PreToolUse` hook.
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
            Call::Shell(_) if tools::FOREIGN_SHELL => return None,
            Call::Shell(command) => (
                "bash".to_owned(),
                json!({ "command": command, "description": "bench" }),
            ),
            Call::Read(path) => ("view".to_owned(), json!({ "file_path": at.file(path) })),
            Call::Write(path) => (
                "write".to_owned(),
                json!({ "file_path": at.file(path), "content": CONTENT }),
            ),
            Call::Edit(path) => (
                "edit".to_owned(),
                json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
            ),
            Call::Fetch(url) => (
                "fetch".to_owned(),
                json!({ "url": url, "format": "text" }),
            ),
            // `mcp_<server>_<tool>` cannot be split back into the server and
            // the tool, so the policy's per-server MCP rules do not apply to
            // Crush's MCP calls (HOST.md): the bench's MCP scenarios, written
            // for them, are not Crush's to meet.
            Call::Mcp { .. } => return None,
        };
        Some(bench::payload(&tool, &input, at))
    }

    /// Crush reads `ask` as no decision.
    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit, false)
    }

    /// A `review` must reach Crush as a deny: it cannot ask the person.
    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        match verdict {
            Verdict::Review => Answer::Deny,
            other => other.into(),
        }
    }
}

#[cfg(test)]
mod tests;
