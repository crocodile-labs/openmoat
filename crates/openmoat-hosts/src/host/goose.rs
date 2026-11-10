//! goose (Block's open-source agent, `aaif-goose/goose`): its `PreToolUse`
//! command hook, run from a plugin.
//!
//! Hooks: `documentation/docs/guides/context-engineering/hooks.md` in the
//! repository (the project moved from `block/goose`); behaviour checked against the source of `aaif-goose/goose` v1.57.0
//! (`crates/goose/src/hooks/mod.rs`, `plugins/discovery.rs`,
//! `config/paths.rs`, `agents/state_machine/ops_toolcalling.rs`,
//! `agents/platform_extensions/`), 2026-11-03.
//!
//! goose loads hooks from `hooks/hooks.json` in each plugin directory it
//! finds: `~/.agents/plugins/<name>/` for the person, and
//! `<project>/.agents/plugins/<name>/` for the directory goose started in.
//! OpenMoat's plugin is `openmoat`. The file is the Open Plugins layout:
//! `{"hooks": {"PreToolUse": [{"matcher", "hooks": [{"type": "command",
//! "command", "timeout", "on_failure"}]}]}}`. goose runs `command` with
//! `sh -c` (on Windows too) and this JSON on stdin: `event` (`PreToolUse`),
//! `session_id`, `matcher_context` (the tool name), `tool_call_id`,
//! `tool_name`, `tool_input` (absent for a call with no arguments) and
//! `working_dir`, the session's directory, which goose resolves a relative
//! path against.
//!
//! The answer: exit 2 blocks with stderr as the reason, and so does
//! `{"decision": "block", "reason"}` on stdout whatever the exit code; exit 0
//! with nothing on stdout or `{"decision": "allow"}` lets the call run. There
//! is no prompt. goose has already put its own approval to the person (its
//! `GOOSE_MODE`) before it runs the hook, so nothing skips it.
//!
//! Anything else (a hook that cannot start, times out, exits non-zero without
//! a block, prints anything else or gets no payload) is a hook failure: the
//! call runs, unless the entry says `on_failure: block`, which OpenMoat's does
//! ([`hook_file::Goose`]).

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    Reviews, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, Location, McpFile, McpSpec,
    ProjectSettingsSpec, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError, Replacement};

mod bench;
mod doc;
pub(crate) mod hook_file;
mod location;
mod mcp;
mod project_settings;
mod protect;
mod tools;

/// The one event OpenMoat answers.
pub(crate) const EVENT: &str = "PreToolUse";

/// Seconds goose waits for the hook (its default is 30). goose cannot prompt, so
/// the hook never waits on a person; a timed-out hook blocks the call
/// (`on_failure: block`). Above [`crate::GUARD_BUDGET_S`], so the guard's own
/// deny arrives first.
const HOOK_TIMEOUT_S: u64 = 60;
const _: () = assert!(crate::GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// No matcher: the hook runs for every tool, MCP extensions' included. The
/// entry sets `on_failure: block` itself ([`hook_file::Goose`]).
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false)];

/// goose has no `review`: a hook allows or blocks.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "goose",
    display_name: "goose",
    reviews: Reviews {
        on_pre_tool_use: Some("goose hooks cannot prompt"),
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "blocks the call when the hook cannot start (goose runs it with `sh`, on \
         Windows too), times out, gets no payload, exits non-zero without a block or prints \
         anything but a decision (`on_failure: block`, which `openmoat init` sets); runs every \
         call unchecked when goose does not load OpenMoat's plugin: listed in \
         `disabledPlugins` of a `settings.json`, set `enabled: false` under `plugins` in \
         `config.yaml`, replaced by a project plugin named `openmoat`, or a `hooks.json` goose \
         cannot read",
    gaps: "no OS sandbox from OpenMoat; Code Mode's `execute_javascript` calls other tools \
         without the hook, so it needs review (a deny in goose); goose loads plugins once, from the \
         directory it starts in: a project's `.agents/plugins/` can add hooks or a plugin named \
         `openmoat` that replaces OpenMoat's, and its `.config/goose/settings.json` can turn \
         OpenMoat's off (`openmoat status` and `doctor` report goose not protected in a \
         directory whose plugin replaces OpenMoat's, and warn about the settings and the other \
         plugins' hooks); `plugins` in `config.yaml` can turn it off; the shell on Windows is `cmd` \
         (or `GOOSE_SHELL`), which OpenMoat leaves to goose; with `GOOSE_PATH_ROOT` the moved \
         plugin directory is pinned but not in the default policy; a changed `hooks.json` is \
         caught on the next call",
    install: Some(InstallSpec {
        dir_variable: location::ROOT_VARIABLE,
        dir_name: location::DIR_NAME,
        config_file: location::HOOK_FILE_NAME,
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&hook_file::Goose),
        location: Location::Custom(&location::LOCATE),
        ..InstallSpec::BASE
    }),
    // `extensions` in `config.yaml` (`config/extensions.rs`); goose reads no
    // project file of servers. A tool is `<extension>__<tool>`.
    mcp: Some(McpSpec {
        user_file: McpFile::InConfigDir("config.yaml"),
        user_reader: &mcp::Extensions,
        project_files: &[],
        tool_names: &mcp::GooseNames,
        auto_start: None,
    }),
    // `enabledPlugins` and `disabledPlugins` in `.config/goose/settings.json`
    // and `settings.local.json` of the directory goose starts in, over the
    // person's `settings.json` (`plugins/discovery.rs`). The plugins of that
    // directory's `.agents/plugins` load beside the person's, and one named
    // `openmoat` in place of OpenMoat's.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".config/goose",
        shared: "settings.json",
        local: Some("settings.local.json"),
        more: &[],
        hook_dir: None,
        plugin_dir: Some(location::PROJECT_PLUGINS),
        reader: &project_settings::READER,
        user_file: "settings.json",
        user_more: &[],
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    docs: doc::DOCS,
    // Tools take `GOOSE_SHELL`; hooks are `sh -c` (ADR-075).
    tool_token: crate::ToolToken::Wrapper {
        vars: &["GOOSE_SHELL"],
        on_path: false,
    },
    // The session and log directories of its logging page (ADR-076); its
    // configuration directory is not listed: `config.yaml` is `kernel-self`'s.
    run: crate::RunFacts::Known {
        program: "goose",
        args: &[],
        writes: &[
            crate::RunWrite::Home(".local/share/goose"),
            crate::RunWrite::Home(".local/state/goose"),
        ],
    },
    run_env: &["GOOSE_PROVIDER", "GOOSE_MODEL", "GOOSE_PROVIDER__API_KEY"],
    ..HostSpec::BASE
};

/// goose's `PreToolUse` hook.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// goose names the event in `event`, not `hook_event_name`: a payload
    /// that has the latter is another host's.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None => parse(host, payload),
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
    event: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<Value>,
    #[serde(default)]
    working_dir: Option<String>,
}

fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let event = p.event.unwrap_or_default();
    if event != EVENT {
        return Err(wrong_event(Some(&event)));
    }
    let tool = p
        .tool_name
        .filter(|t| !t.is_empty())
        .ok_or(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "tool_name",
        })?;
    // goose leaves `tool_input` out for a call with no arguments; any that
    // are there are the tool's argument object.
    let input = match p.tool_input {
        None | Some(Value::Null) => Value::Object(serde_json::Map::new()),
        Some(input @ Value::Object(_)) => input,
        Some(_) => {
            return Err(HostError::MalformedArguments {
                tool,
                problem: "`tool_input` is not an object".to_owned(),
            });
        }
    };
    let mapped = tools::map(&tool, &input)?;
    // `write` replaces the whole file with `content`; `edit` replaces the one
    // occurrence of `before` with `after`.
    let (content, edits) = match tool.as_str() {
        "write" => (string(&input, "content"), Vec::new()),
        "edit" => match (string(&input, "before"), string(&input, "after")) {
            (Some(old), Some(new)) => (None, vec![Replacement { old, new, all: false }]),
            _ => (None, Vec::new()),
        },
        _ => (None, Vec::new()),
    };
    let mcp_arguments = crate::wire::mcp_call::hook_arguments(mapped.action.as_ref(), &input);
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id.filter(|s| !s.is_empty())),
        call_id: p.tool_call_id.filter(|id| !id.is_empty()),
        cwd: p.working_dir.filter(|c| !c.is_empty()),
        tool: mapped.tool.unwrap_or(tool),
        action: mapped.action,
        content,
        edits,
        patch: None,
        mcp_arguments,
        sandboxed: false,
        event: HookEvent::PreToolUse,
    })
}

fn string(input: &Value, key: &str) -> Option<String> {
    input.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Nothing for `defer` (ADR-025): goose runs the call as it would without
/// OpenMoat, its own approval already given. `allow` says so; `deny`, and any
/// verdict that reaches here without being answered, blocks with the reason
/// goose returns to the model. A `review` arrives as a `deny` ([`SPEC`]'s reviews); goose's protocol has no
/// word for it, so no verdict word is ever sent (`wire::host_verdict` is not needed).
pub(crate) fn render(decision: &Decision) -> String {
    match decision.verdict {
        Verdict::Defer => String::new(),
        Verdict::Allow => serde_json::json!({ "decision": "allow" }).to_string(),
        _ => serde_json::json!({
            "decision": "block",
            "reason": crate::reason_line(decision),
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests;
