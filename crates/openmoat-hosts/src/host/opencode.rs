//! OpenCode 1 (`opencode-ai`): the `tool.execute.before` plugin hook.
//!
//! OpenCode has no command hook; a plugin's `tool.execute.before` handler runs
//! before every tool call, built-in, custom, a plugin's and an MCP server's,
//! and a handler that throws blocks the call: the model sees the error and the
//! session goes on (OpenCode 1.19.4 `packages/opencode/src/session/tools.ts`,
//! `session/processor.ts`; `packages/web/src/content/docs/plugins.mdx`). OpenCode
//! waits for the handler without a limit. OpenMoat's plugin
//! (`host/opencode/integration/openmoat.js`) runs `moat guard --host opencode`
//! with this JSON on stdin: `hook_event_name` (`tool.execute.before`), the
//! hook's own `tool`, `sessionID` and `callID`, its `args`, and four fields the
//! plugin adds: `directory` and `worktree` (the instance the plugin was loaded
//! for; OpenCode's tools resolve relative paths against `directory`),
//! `mcpServers` (the names under `mcp` in OpenCode's merged configuration,
//! from the plugin's `config` hook) and `platform` (`process.platform`).
//!
//! Output: nothing for `defer`, else `{"decision": "allow" | "deny", "reason"}`.
//! The plugin returns for `allow` and throws the reason for `deny`; anything
//! else it cannot read blocks the call. OpenCode 1 has no way for a plugin to
//! ask the person (`permission.ask` is declared but never called since 1.3.0),
//! so an `ask` reaches it as a deny that says how to approve the call.
//!
//! OpenCode 2 (`@opencode/cli`, 2.0.0 and later) loads plugins through another
//! API and does not run this one; `moat init` does not set it up
//! ([`InstallSpec::unsupported`]).

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call as BenchCall, Exit, Place};
use crate::contract::{
    Asks, GUARD_BUDGET_S, HookDir, HookLayout, HookSpec, HostAdapter, HostSpec, InstallSpec,
    Location, McpFile, McpSpec, ProjectSettingsSpec, Unsupported, wrong_event,
};
use crate::wire::owned_file::OwnedFile;
use crate::{HookEvent, HookRequest, Host, HostError};

mod bench;
mod doc;
mod location;
mod mcp;
mod project_settings;
mod protect;
mod tools;

/// Seconds OpenMoat's plugin waits for `moat guard` before it blocks the call
/// (`GUARD_TIMEOUT_MS` in `opencode/integration/openmoat.js`, which
/// `opencode/tests.rs` compares with this). OpenCode waits for a `tool.execute.before`
/// handler without a limit of its own.
pub(crate) const HOOK_TIMEOUT_S: u64 = 45;
const _: () = assert!(GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// OpenCode runs `tool.execute.before` for every tool and blocks the call when
/// a handler throws.
const HOOKS: &[HookSpec] = &[HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false)];

pub(crate) const EVENT: &str = "tool.execute.before";

/// The plugin's file in OpenCode's configuration directory: OpenCode 1 loads
/// every `.js` and `.ts` file in its `plugin/` and `plugins/` at start
/// (`config/plugin.ts`, `ConfigPlugin.load`).
const PLUGIN_FILE: &str = "plugins/openmoat.js";

/// OpenMoat's plugin, which is OpenCode's hook file: `moat init` writes it to
/// `<config dir>/plugins/openmoat.js` with the binary's path filled in.
static PLUGIN: OwnedFile = OwnedFile {
    name: "OpenCode plugin",
    source: include_str!("opencode/integration/openmoat.js"),
    first_line: "// OpenMoat for OpenCode.",
};

/// OpenCode 1 cannot ask: an `ask` is a deny that says how to approve it.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "opencode",
    display_name: "OpenCode",
    asks: Asks {
        on_pre_tool_use: Some("OpenCode 1 gives plugins no way to ask the person"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
        ..Asks::BASE
    },
    on_hook_failure: "blocks the call when OpenMoat's plugin throws (OpenCode's \
         `tool.execute.before` fails closed), and the plugin blocks when `openmoat` is \
         missing, crashes or does not answer within 45 s; runs the call unchecked when \
         OpenCode does not load the plugin (`--pure`, `OPENCODE_PURE`, or an error \
         loading it)",
    gaps: "no OS sandbox from OpenMoat; OpenCode 1 plugins cannot ask, so an ask is a \
         deny that says how to approve it; OpenCode 2 is not supported yet; other \
         plugins and custom tools run in OpenCode's process with the agent's rights, \
         and a project's load at start with no prompt; the person's `!` shell commands \
         are not checked; calls run unchecked if OpenCode does not load the plugin \
         (`--pure`, `OPENCODE_PURE`, a load error); a failed or slow hook blocks the \
         call",
    // `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`
    // (`packages/core/src/global.ts`, `xdg-basedir`). OpenCode always loads
    // the plugins there, also when `OPENCODE_CONFIG_DIR` names another
    // directory to read as well (`config/paths.ts`, `directories`).
    install: Some(InstallSpec {
        dir_variable: location::VARIABLE,
        dir_name: location::DIR_NAME,
        config_file: PLUGIN_FILE,
        hooks: HOOKS,
        hook_file: HookLayout::Owned(&PLUGIN),
        location: Location::Custom(&location::LOCATE),
        unsupported: Some(Unsupported {
            program: "opencode",
            from_major: 2,
            why: "OpenCode 2 loads plugins through a new API that OpenMoat's plugin does \
                 not support yet; OpenMoat supports OpenCode 1 (`opencode-ai`)",
        }),
        ..InstallSpec::BASE
    }),
    // `mcp.<name>` in the configuration files OpenCode merges: the global
    // `config.json`, `opencode.json` and `opencode.jsonc`, and a project's
    // `opencode.json[c]` and `.opencode/opencode.json[c]`
    // (`config/config.ts`; `docs/mcp-servers.mdx`).
    mcp: Some(McpSpec {
        user_file: McpFile::EachInConfigDir(&["config.json", "opencode.json", "opencode.jsonc"]),
        user_reader: &mcp::OpenCodeJson,
        project_files: &[
            ("opencode.json", &mcp::OpenCodeJson),
            ("opencode.jsonc", &mcp::OpenCodeJson),
            (".opencode/opencode.json", &mcp::OpenCodeJson),
            (".opencode/opencode.jsonc", &mcp::OpenCodeJson),
        ],
        tool_names: &mcp::Joined,
    }),
    // A project's `opencode.json` and `.opencode/opencode.json` add plugins,
    // MCP servers and permission rules, and its `.opencode/plugins/` load in
    // OpenCode's process at start, with no prompt (`config/config.ts`,
    // `config/paths.ts`). OpenCode 1 has no setting that removes a plugin, so
    // the person's own file cannot turn OpenMoat's off. Writes to these files
    // ask (`runs-later` in the default policy).
    project_settings: Some(ProjectSettingsSpec {
        dir: "",
        shared: "opencode.json",
        local: Some(".opencode/opencode.json"),
        hook_dir: Some(HookDir {
            path: ".opencode/plugins",
            extensions: &["js", "ts"],
        }),
        reader: &project_settings::READER,
        user_file: "opencode.json",
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// What OpenMoat's plugin sends from `tool.execute.before`.
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

    fn bench_payload(&self, call: &BenchCall, at: &Place<'_>) -> Option<String> {
        Some(bench::payload(call, at))
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
    tool: String,
    #[serde(default)]
    args: Value,
    #[serde(default, rename = "sessionID")]
    session_id: Option<String>,
    #[serde(default, rename = "callID")]
    call_id: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    mcp_servers: Vec<String>,
    #[serde(default)]
    platform: Option<String>,
}

/// What [`tools::map`] needs to know about one call besides its name and args.
pub(super) struct Call<'a> {
    pub tool: &'a str,
    pub args: &'a Value,
    pub cwd: Option<&'a str>,
    pub mcp_servers: &'a [String],
    pub windows: bool,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    if p.tool.is_empty() {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "tool",
        });
    }
    let cwd = p.directory.filter(|c| !c.is_empty());
    let call = Call {
        tool: &p.tool,
        args: &p.args,
        cwd: cwd.as_deref(),
        mcp_servers: &p.mcp_servers,
        windows: p.platform.as_deref() == Some("win32"),
    };
    let action = tools::map(&call)?;
    // `write` replaces the whole file with `content`.
    let content = match (p.tool.as_str(), &action) {
        ("write", Some(Action::FsWrite { .. })) => p
            .args
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id.filter(|s| !s.is_empty())),
        call_id: p.call_id.filter(|c| !c.is_empty()),
        cwd,
        tool: p.tool,
        action,
        content,
        event: HookEvent::PreToolUse,
    })
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025): no decision, so OpenCode's own permission rules
    // decide, as without OpenMoat.
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    serde_json::json!({
        "decision": decision.verdict.as_str(),
        "reason": crate::reason_line(decision),
    })
    .to_string()
}

#[cfg(test)]
mod tests;
