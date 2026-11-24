//! The Codex CLI: `PreToolUse` in Claude Code's format
//! ([`crate::wire::pre_tool_use`]), and `PostToolUse` for what a call
//! returned ([`post_tool_use`]).

use openmoat_core::{Decision, Verdict};
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{
    Reviews, CONFIG_HOOK_TIMEOUT_S, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec, McpCallIds, McpFile, McpSpec, Prefixed,
    ProjectSettingsSpec, ProxySessions, SandboxFormat, SandboxSpec,
    TOOL_HOOK_TIMEOUT_S, wrong_event,
};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

mod hook_off;
mod advisories;
mod doc;
mod hook_file;
mod mcp;
mod post_tool_use;
mod project_settings;
mod tools;
mod trust;
mod weekly;
mod windows_sandbox;

#[cfg(test)]
mod tests;

/// Codex runs `PreToolUse` for shell, `apply_patch` file edits, MCP tools and
/// its local tools, which it names by their function (`read_mcp_resource`,
/// `view_image`); web search and hosted tools have no hook, and `write_stdin`
/// "doesn't run `PreToolUse` again". Codex has no key that blocks a
/// call whose hook fails: "a failed `PreToolUse` hook marks that hook run as
/// failed, reports the error, and continues the tool call"
/// (<https://learn.chatgpt.com/docs/hooks>), so `guard` itself must answer.
/// `PostToolUse` reports what a call returned (ADR-063), for the tools whose
/// output may be content an attacker controls: a shell command (`curl`, `gh
/// issue view`) and an MCP result. It runs after the call and has nothing to
/// block.
const HOOKS: &[HookSpec] = &[
    HookSpec::new(
        "PreToolUse",
        "Bash|apply_patch|read_mcp_resource|view_image|mcp__.*",
        TOOL_HOOK_TIMEOUT_S,
        false,
    ),
    HookSpec::new(
        post_tool_use::EVENT,
        "Bash|read_mcp_resource|mcp__.*",
        CONFIG_HOOK_TIMEOUT_S,
        false,
    ),
];

/// Codex's `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and
/// then runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    reviews: Reviews {
        on_pre_tool_use: Some("Codex hooks cannot prompt"),
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "blocks the call when `openmoat` is missing, cannot start or is killed \
         (the hook command exits 2 with a reason itself then); a slow hook is denied by the \
         guard itself after 30 s, before the 600 s limit `openmoat init` writes (ADR-120); \
         runs the call only when the guard cannot answer at all before that limit (stopped, \
         or killed with the hook command)",
    // The hooks page does not say what a failed local hook does; the hook
    // runner's source does: only exit 2 with stderr, or a decision, blocks.
    // So the entry's command turns any status but the guard's 0 or 2 into
    // exit 2 with a reason (`hook_file.rs`, ADR-109). A hook past its
    // `timeout` (seconds, the hooks page) fails and the call runs; the guard
    // answers deny at its deadline first (ADR-120).
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::Blocks,
        times_out: crate::FailureOutcome::GuardDenies(crate::Unanswered::Runs),
        timeout_s: Some(600),
        turned_off_by: "`[features] hooks = false` in `config.toml` (or `requirements.toml`), \
                        turning the hook off in `/hooks`, or a hook Codex has not been told to \
                        trust",
        sources: &[
            "https://learn.chatgpt.com/docs/hooks",
            "https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417",
        ],
    },
    gaps: "web search, hosted tools, code mode's `exec`/`wait` and `request_permissions` are \
         not hooked; what `write_stdin` types into a running command is not hooked, so a \
         command that starts a shell, REPL, editor or login without its own commands needs \
         review; reviews become denies; Codex skips a \
         new or changed hook until the person trusts it in `/hooks`, and `[features] hooks = \
         false` turns hooks off (`openmoat status` and `doctor` report that); a call runs \
         unchecked if the guard cannot answer at all before the hook's time limit (stopped, or \
         killed with the hook command)",
    install: Some(InstallSpec {
        dir_variable: "CODEX_HOME",
        dir_name: ".codex",
        config_file: "hooks.json",
        hooks: HOOKS,
        hook_file: HookLayout::Entries(&hook_file::Codex),
        hook_trust: Some(&trust::Codex),
        // Codex runs a new or changed user hook only once the person trusts it
        // in `/hooks` (Codex's hooks documentation).
        trust_step: Some(
            "open Codex and trust OpenMoat's hooks in /hooks; Codex runs a changed hook only then",
        ),
        // `[features] hooks = false` in `config.toml` turns hooks off. Each
        // session's rollout is `sessions/<yyyy>/<mm>/<dd>/rollout-<time>-<id>.jsonl`,
        // the `transcript_path` its hooks receive; `codex login` writes none.
        // Source: `precompute_new_rollout_path` in
        // https://github.com/openai/codex/blob/main/codex-rs/rollout/src/recorder.rs
        // (`$CODEX_HOME/sessions/YYYY/MM/DD`); rollouts a week old may later be
        // compressed to `.jsonl.zst`, long after they could count.
        liveness: Some(crate::Liveness {
            settings: &["config.toml"],
            sessions: crate::Sessions::Known(&[crate::Activity::new(&[
                "sessions",
                crate::Activity::ANY,
                crate::Activity::ANY,
                crate::Activity::ANY,
            ])
            .ending(".jsonl")]),
            started: None,
        }),
        ..InstallSpec::BASE
    }),
    mcp: Some(McpSpec {
        user_file: McpFile::BesideHookFile("config.toml"),
        user_reader: &mcp::ConfigToml,
        project_files: &[(".codex/config.toml", &mcp::ConfigToml)],
        tool_names: &Prefixed,
        // Codex's `mcp_tool_call.rs` puts `callId` and, for an approved
        // call, `threadId` in the request's `_meta`; the hook's `tool_use_id`
        // and `session_id` for the same call (ADR-107).
        call_ids: Some(McpCallIds {
            session: "threadId",
            call: "callId",
        }),
        auto_start: None,
    }),
    sandbox: Some(SandboxSpec {
        format: SandboxFormat::CodexProfile,
        file: "config.toml",
        unavailable_on_windows: None,
        windows_modes: Some(&windows_sandbox::Codex),
        // Codex's Linux sandbox does not refuse `TIOCSTI`.
        tiocsti_open_on_linux: true,
        // The sandboxing docs (<https://developers.openai.com/codex/sandboxing>):
        // Codex uses the first `bwrap` on `PATH`, else a bundled helper that
        // "requires support for unprivileged user namespace creation", and
        // warns at startup when it cannot create one. So `bwrap` is advised,
        // not needed; the namespace is.
        linux_needs: Some(crate::contract::LinuxSandboxNeeds {
            programs: &[],
            user_namespaces: true,
            without: "Codex warns when it starts, and the commands it runs in its sandbox cannot \
                      start",
            // The same page: on Ubuntu 24.04 load `bwrap-userns-restrict` from
            // `apparmor-profiles`; Ubuntu 25.04's `apparmor` package ships it.
            apparmor: crate::contract::UsernsProfileFix::BwrapUsernsRestrict,
        }),
        // Its upstream proxy comes from the Codex process's own `HTTP_PROXY`,
        // and its hooks cannot set a command's environment (ADR-044).
        proxy_sessions: ProxySessions::NoCredential,
        // `codex --sandbox danger-full-access` runs commands without its sandbox.
        own_sandbox_off: Some("--sandbox danger-full-access"),
    }),
    // A trusted project's `.codex/` layer adds its `config.toml` and
    // `hooks.json`, whose hooks run beside OpenMoat's; `[features] hooks =
    // false` in it or in the user's `config.toml` turns every hook off
    // (<https://learn.chatgpt.com/docs/hooks>).
    project_settings: Some(ProjectSettingsSpec {
        dir: ".codex",
        shared: "config.toml",
        local: Some("hooks.json"),
        more: &[],
        hook_dir: None,
        plugin_dir: None,
        reader: &project_settings::READER,
        user_file: "config.toml",
        user_more: &[],
    }),
    process: crate::contract::ProcessSpec {
        names: &["codex"],
        ..crate::contract::ProcessSpec::BASE
    },
    // `kernel-self` already denies every write under `~/.codex`; these are
    // the files it keeps a login in, which the agent must not read either.
    protect: crate::contract::Protect {
        credentials: &[crate::contract::Paths::new(
            "Codex: its login (ChatGPT tokens or API key) and the file its MCP OAuth\n\
             tokens fall back to without a keyring (`codex-rs/login/src/auth/storage.rs`,\n\
             `rmcp-client/src/oauth.rs`)",
            &["~/.codex/auth.json", "~/.codex/.credentials.json"],
        )],
        runs_later: &[crate::contract::RunsLater::agent_config(
            "Codex: a project's configuration, which can add MCP servers; a write whose\n\
             content turns its hook off (`[features] hooks = false`) is denied before the\n\
             file changes (`project-settings`)",
            &["**/.codex/config.toml"],
        )],
        taint: &[crate::contract::Paths::new(
            "Codex: its directory (configuration, hooks, skills) and a project's",
            &["**/.codex/**"],
        )],
        ..crate::contract::Protect::BASE
    },
    // `$CWD/.agents/skills`, the folders above it to `$REPO_ROOT/.agents/skills`,
    // and `$HOME/.agents/skills` (<https://learn.chatgpt.com/docs/build-skills>)
    conventions: &[crate::contract::AGENT_SKILLS],
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    // Codex 0.166 sends a call's own working directory (a shell call's
    // `workdir`) as `cwd` (`command_input_cwd` in
    // `hooks/src/events/pre_tool_use.rs`) and starts every hook in the
    // session's directory.
    session_dir: crate::contract::SessionDir::HookProcess,
    // `requirements.toml` (<https://learn.chatgpt.com/docs/hooks>, "Managed
    // hooks"): `[features] hooks = false` there forces every hook off, and
    // `allow_managed_hooks_only` skips the person's, project and plugin
    // hooks, running only the managed `[hooks]`.
    system_settings: Some(crate::contract::SystemSettingsSpec {
        files: &[
            crate::contract::SystemFile::at(
                "/etc/codex/requirements.toml",
                &[crate::contract::Platform::MacOs, crate::contract::Platform::Linux, crate::contract::Platform::Wsl],
            ),
            crate::contract::SystemFile::at(
                "C:/ProgramData/OpenAI/Codex/requirements.toml",
                &[crate::contract::Platform::Windows],
            ),
        ],
        drop_ins: None,
        managed_only: Some("allow_managed_hooks_only"),
        hooks_key: "hooks",
    }),
    tool_token: crate::ToolToken::NotWithheld {
        why: "Codex picks its shell from the login record, and its tool environment setting is \
              not yet confirmed to leave the person's own exclusions in place",
    },
    run_env: &["OPENAI_API_KEY", "CODEX_ACCESS_TOKEN"],
    weekly: weekly::WEEKLY,
    hook_off: hook_off::HOOK_OFF,
    // "Plugin hooks are not eligible for the public Plugins Directory"
    // (<https://learn.chatgpt.com/docs/plugins>), and a hook Codex runs needs
    // the person's trust in `/hooks` either way.
    plugin: crate::contract::Plugin::None {
        why: "Codex's Plugins Directory does not take plugins that carry hooks \
              (https://learn.chatgpt.com/docs/plugins); `openmoat init` writes the hook, which \
              you then trust in Codex's `/hooks`",
    },
    // The project's own files that hold hooks laid out as the hook file
    // (ADR-109).
    ledger: crate::Ledger {
        project_hook_files: &["hooks.json"],
        ..crate::Ledger::BASE
    },
    ..HostSpec::BASE
};

/// Codex sends `PreToolUse`, and `PostToolUse` once `init` installed it.
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
            None | Some(pre_tool_use::EVENT) => {
                let mut request = pre_tool_use::parse_with(host, payload, tools::own)?;
                request.action = request.action.map(tools::held);
                Ok(request)
            }
            Some(post_tool_use::EVENT) => post_tool_use::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    /// `PostToolUse` is what a call returned (ADR-057).
    fn event_of(&self, event: &str) -> HookEvent {
        match event {
            post_tool_use::EVENT => HookEvent::PostToolUse {
                output: String::new(),
            },
            _ => HookEvent::PreToolUse,
        }
    }

    fn render(&self, event: &HookEvent, decision: &Decision) -> String {
        // Nothing for what a call returned, whatever was decided: a
        // `decision: "block"` there replaces the result the model sees.
        if matches!(event, HookEvent::PostToolUse { .. }) {
            return String::new();
        }
        // Codex accepts `permissionDecision: "allow"` only with `updatedInput`;
        // a bare allow is "unsupported", reported as a failed hook (rust-v0.163.0
        // and rust-v0.166.0 hooks/src/engine/output_parser.rs). No output is
        // Codex's "no objection": its own approval flow then runs, as it would
        // after an allow, which cannot skip it.
        if decision.verdict == Verdict::Allow {
            return String::new();
        }
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

    /// Codex cannot prompt, so a `review` has to arrive as a blocking `deny`; an
    /// `allow` is no output, which Codex reads as no objection.
    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        match verdict {
            Verdict::Review => Answer::Deny,
            Verdict::Allow => Answer::Passthrough,
            other => other.into(),
        }
    }
}
