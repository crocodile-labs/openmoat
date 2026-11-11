//! Antigravity CLI (`agy`, Google's successor to the Gemini CLI for its own
//! sign-in): the `PreToolUse` command hook.
//!
//! Every fact below is from the official documentation, read 2026-11-09 (no
//! version is stated there): <https://antigravity.google/docs/hooks?tab=cli>,
//! `/docs/sandbox/`, `/docs/permissions/`, `/docs/mcp?tab=cli`,
//! `/docs/settings?tab=cli` and `/docs/install?tab=cli`. Nothing here was
//! checked against a running `agy`; the fixtures say the same.
//!
//! Hook files: `~/.gemini/config/hooks.json` for the person, shared with the
//! Antigravity app and IDE, `<workspace>/.agents/hooks.json` for a project, a
//! plugin's `hooks.json`. Each top-level key is a hook's name, holding
//! `enabled` and one list per event; the hooks in `settings.json` are not
//! loaded.
//!
//! Input is camelCase JSON on stdin: `conversationId`, `workspacePaths`,
//! `transcriptPath`, `artifactDirectoryPath`, `modelName`, `lastUserInput`,
//! and for `PreToolUse` `toolCall` (`name`, `args`) and `stepIdx`. It names
//! neither its event nor a working directory.
//!
//! Output is JSON on stdout with a required `decision`: `allow` defers to the
//! next hook or the default policy, `auto_approve` approves where the default
//! policy would prompt, `deny` blocks, `ask` prompts but honours "Always
//! Allow", `force_ask` always prompts, ignoring cached permissions,
//! `deny_unless_prior_grant` denies unless a grant covers it. `overwrite` can
//! rewrite the call's arguments; OpenMoat never sends it.
//!
//! What the documentation leaves out (the exit codes, what a hook that
//! crashes, times out or prints bad JSON does, how hook files merge, whether
//! MCP or subagent calls fire hooks, what `force_ask` does where no one can
//! answer) is assumed to work against OpenMoat: see `SPEC` and `HOST.md`.

use openmoat_core::{Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call, Exit, Place};
use crate::contract::{
    HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, Location, McpFile, McpServersJson,
    McpSpec, ProjectSettingsSpec, Reviews, TOOL_HOOK_TIMEOUT_S, Unseen, wrong_event,
};
use crate::{HookEvent, HookRequest, Host, HostError, Replacement};

mod bench;
mod doc;
pub(crate) mod hook_file;
mod location;
mod mcp;
mod project_settings;
mod protect;
mod settings;
mod tools;

/// The one event OpenMoat answers.
pub(crate) const EVENT: &str = "PreToolUse";

/// `*` matches every tool (`""` does as well, by the documentation). 600 s
/// outlasts the guard's own budget; the documented default of 30 s does not.
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "*", TOOL_HOOK_TIMEOUT_S, false)];

/// Antigravity CLI puts a `review` to the person itself, `force_ask` so a
/// cached "Always Allow" cannot answer it; the payload does not say whether a
/// person is there to see it.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "antigravity-cli",
    display_name: "Antigravity CLI",
    reviews: Reviews {
        on_pre_tool_use: None,
        on_no_prompt: Some(
            "Antigravity CLI would run it without asking you (`toolPermission: always-proceed`)",
        ),
        defer_is_review_on_no_prompt: false,
        unseen: Some(Unseen {
            env: &[],
            file: Some("settings.json"),
            config: settings::approves_unseen,
        }),
        ..Reviews::BASE
    },
    on_hook_failure: "not documented: what Antigravity CLI does when the hook cannot start, \
         crashes, times out, exits non-zero or prints something that is not its JSON is not \
         stated, and no setting to block on failure is documented, so OpenMoat assumes the call \
         runs (the guard itself answers a deny and exits 2 on every error it can catch)",
    gaps: "hook only: no OS sandbox from OpenMoat (`enableTerminalSandbox` is the person's to \
         set, or `openmoat run`); preview: OpenMoat's hook for Antigravity CLI is new; what \
         the hook sees is taken from the documentation: whether MCP and subagent calls fire hooks, \
         and the name a hook receives for an MCP tool, are not documented, so `invoke_subagent`, \
         `define_subagent` and `schedule` need review; a hook file or plugin of a project \
         can add hooks that rewrite a call's arguments (`overwrite`) after OpenMoat checked it, \
         and how a project's `.agents/hooks.json` merges with the person's is not documented \
         (`openmoat status` and `doctor` warn about one, and report a project entry that sets \
         OpenMoat's off); whether hooks run in a workspace the CLI does not trust and where \
         `/hooks` keeps its on/off state are not documented; `--dangerously-skip-permissions` auto-approves permission \
         requests, which OpenMoat cannot see (a saved `toolPermission: always-proceed` it reads, \
         and a review there is a deny), and whether `force_ask` reaches a person there or \
         under `-p` is not documented; a call in a multi-root session is decided against the first workspace; \
         `PostToolUse` carries no output, so no injected-input checks; \
         plugins under `~/.gemini/config/plugins` are written only by a person (`kernel-self`) \
         but are not reported; the shell that runs hooks and `run_command` on Windows is not \
         documented",
    // A preview host until the weekly check shows the hook deciding a real
    // agy's call (`HOST.md`, "The first real run").
    limit: Some(
        "preview: OpenMoat's hook for Antigravity CLI is new; use `openmoat run` (`--isolate` \
         on Linux) for an OS boundary until it leaves preview. Antigravity CLI does not \
         document what happens when the hook fails, and `--dangerously-skip-permissions` \
         approves requests unseen",
    ),
    install: Some(InstallSpec {
        // No variable moves its directory; `~` is the home directory.
        dir_variable: "HOME",
        dir_name: location::DIR_NAME,
        config_file: location::HOOK_FILE,
        hooks: HOOKS,
        dir_variable_is_home: true,
        hook_file: HookLayout::Entries(&hook_file::Named),
        location: Location::Custom(&location::LOCATE),
        ..InstallSpec::BASE
    }),
    // `~/.gemini/config/mcp_config.json` and `<workspace>/.agents/mcp_config.json`
    // (/docs/mcp); a tool is `mcp_<server>_<tool>`, or `call_mcp_tool` for a lazy one.
    mcp: Some(McpSpec {
        user_file: McpFile::BesideHookFile("mcp_config.json"),
        user_reader: &McpServersJson,
        project_files: &[(".agents/mcp_config.json", &McpServersJson)],
        tool_names: &mcp::Names,
        auto_start: None,
    }),
    // `<workspace>/.agents/` holds a project's hooks, MCP servers and plugins.
    project_settings: Some(ProjectSettingsSpec {
        dir: ".agents",
        shared: "hooks.json",
        local: None,
        more: &["mcp_config.json"],
        hook_dir: None,
        plugin_dir: Some(project_settings::PROJECT_PLUGINS),
        reader: &project_settings::READER,
        user_file: "settings.json",
        user_more: &[],
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    docs: doc::DOCS,
    tool_token: crate::ToolToken::NotWithheld {
        why: "its documentation does not say how tool commands and hooks start",
    },
    // What its MCP page says the CLI writes; `agy` itself was not run (ADR-076).
    run: crate::RunFacts::Known {
        program: "agy",
        args: &[],
        writes: &[crate::RunWrite::Home(".gemini/antigravity-cli")],
    },
    ..HostSpec::BASE
};

/// Antigravity CLI's `PreToolUse` hook.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// The payload names no event: one that does is another host's.
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
#[serde(rename_all = "camelCase")]
struct Payload {
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    workspace_paths: Vec<String>,
    #[serde(default)]
    tool_call: Option<ToolCall>,
    #[serde(default)]
    step_idx: Option<u64>,
    /// `PostToolUse` only: "empty on success".
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Deserialize)]
struct ToolCall {
    #[serde(default)]
    name: String,
    #[serde(default)]
    args: Value,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    // Only `PreToolUse` and `PostToolUse` carry `toolCall`, and only the
    // latter `error`; the other events have neither to read.
    if p.error.is_some() {
        return Err(wrong_event(Some("PostToolUse")));
    }
    let Some(call) = p.tool_call else {
        return Err(wrong_event(None));
    };
    if call.name.is_empty() {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "toolCall.name",
        });
    }
    // The payload has no working directory: the first workspace stands in, as
    // Cursor's `workspace_roots` do.
    let cwd = p.workspace_paths.into_iter().find(|w| !w.is_empty());
    let mapped = tools::map(&call.name, &call.args, cwd.as_deref())?;
    let (content, edits) = written(&call.name, &call.args);
    // A lazy MCP call's arguments are its `Arguments`, not the call's own.
    let mcp_input = call.args.get("Arguments").filter(|_| call.name == "call_mcp_tool");
    let mcp_arguments = crate::wire::mcp_call::hook_arguments(
        mapped.action.as_ref(),
        mcp_input.unwrap_or(&call.args),
    );
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.conversation_id.filter(|s| !s.is_empty())),
        call_id: p.step_idx.map(|step| step.to_string()),
        cwd,
        tool: mapped.tool.unwrap_or(call.name),
        action: mapped.action,
        content,
        edits,
        patch: None,
        mcp_arguments,
        sandboxed: false,
        event: HookEvent::PreToolUse,
    })
}

/// What a write tool leaves in the file: `write_to_file`'s `CodeContent`,
/// or `replace_file_content`'s replacement. `multi_replace_file_content`'s
/// chunks are not read: the documentation lists no keys inside them, and the
/// call stands as the policy decides it.
fn written(tool: &str, args: &Value) -> (Option<String>, Vec<Replacement>) {
    let text = |key: &str| args.get(key).and_then(Value::as_str).map(str::to_owned);
    match tool {
        "write_to_file" => (text("CodeContent"), Vec::new()),
        "replace_file_content" => match (text("TargetContent"), text("ReplacementContent")) {
            (Some(old), Some(new)) => (
                None,
                vec![Replacement {
                    old,
                    new,
                    all: args.get("AllowMultiple").and_then(Value::as_bool).unwrap_or(false),
                }],
            ),
            _ => (None, Vec::new()),
        },
        _ => (None, Vec::new()),
    }
}

/// `decision` as Antigravity CLI reads it. A `defer` answers `allow`, which
/// the documentation defines as deferring to the next hook or the default
/// policy; `decision` is required, so "no output" is not an answer it names.
/// A `review` answers `force_ask`, so no cached permission can answer it.
pub(crate) fn render(decision: &Decision) -> String {
    let word = match decision.verdict {
        Verdict::Review => "force_ask",
        Verdict::Allow | Verdict::Defer => "allow",
        // `Verdict` may grow: anything but the above blocks.
        _ => "deny",
    };
    let mut reply = serde_json::json!({ "decision": word });
    if matches!(decision.verdict, Verdict::Deny | Verdict::Review) {
        reply["reason"] = Value::from(crate::reason_line(decision));
    }
    reply.to_string()
}

#[cfg(test)]
mod tests;
