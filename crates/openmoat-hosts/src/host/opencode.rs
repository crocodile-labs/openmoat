//! OpenCode 1 (`opencode-ai`, 1.3.4 and later) and OpenCode 2 (`@opencode/cli`)
//! through one plugin (ADR-040).
//!
//! OpenCode has no command hook. OpenMoat's plugin
//! (`host/opencode/integration/openmoat.js`) exports `{ id, server, setup }`:
//! OpenCode 1 calls `server` and runs its `tool.execute.before` handler before
//! every tool call (1.19.4 `packages/opencode/src/session/tools.ts`); OpenCode 2
//! calls `setup`, which registers `ctx.tool.hook("execute.before")` (2.2.0
//! `packages/core/src/tool.ts`, `core/src/plugin/hooks.ts`). In both, a
//! handler that throws blocks the call and the model sees the error, and
//! OpenCode waits for the handler without a limit. The plugin runs `moat guard
//! --host opencode` with this JSON on stdin:
//!
//! - OpenCode 1: `hook_event_name` `tool.execute.before`, the hook's `tool`,
//!   `sessionID`, `callID` and `args`;
//! - OpenCode 2: `hook_event_name` `execute.before`, the hook's `tool`,
//!   `sessionID`, `agent`, `messageID`, its `id` as `callID`, and `input`;
//!
//! and in both four fields the plugin adds: `directory` and `worktree` (the
//! instance the plugin was loaded for; tools resolve relative paths against
//! `directory`), `mcpServers` (the configured MCP servers' names) and
//! `platform` (`process.platform`).
//!
//! Output: nothing for `defer`, else `{"decision": "allow" | "ask" | "deny",
//! "reason"}`. The plugin returns for `allow`, throws the reason for `deny`,
//! and on OpenCode 2 puts an `ask` to the person through OpenCode's own
//! permission prompt; anything else it cannot read blocks the call. OpenCode 1
//! has no way for a plugin to ask the person (`permission.ask` is declared but
//! never called since 1.3.0), so there an `ask` arrives as a deny that says how
//! to approve the call (`HookEvent::PreToolUseNoAsk`).

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::bench::{Answer, Call as BenchCall, Exit, Place};
use crate::contract::{
    AlsoDir, Asks, GUARD_BUDGET_S, Heartbeat, HookDir, HookLayout, HookSpec, HookVersions,
    HostAdapter,
    HostSpec, InstallSpec, Location, McpFile, McpSpec, ProjectSettingsSpec, wrong_event,
};
use crate::wire::owned_file::OwnedFile;
use crate::{HookEvent, HookRequest, Host, HostError};

mod advisories;
mod bench;
mod doc;
mod location;
mod mcp;
mod project_settings;
mod protect;
mod tools;

/// Seconds OpenMoat's plugin waits for `moat guard` before it blocks the call
/// (`GUARD_TIMEOUT_MS` in `opencode/integration/openmoat.js`, which
/// `opencode/tests.rs` compares with this). OpenCode waits for a hook without
/// a limit of its own.
pub(crate) const HOOK_TIMEOUT_S: u64 = 45;
const _: () = assert!(GUARD_BUDGET_S < HOOK_TIMEOUT_S);

/// OpenCode 1's hook, as the plugin names it in its payload.
pub(crate) const EVENT: &str = "tool.execute.before";
/// OpenCode 2's hook (`ctx.tool.hook("execute.before")`).
pub(crate) const EVENT_V2: &str = "execute.before";

/// Each version runs its hook for every tool and blocks the call when a
/// handler throws.
const HOOKS: &[HookSpec] = &[
    HookSpec::new(EVENT, "", HOOK_TIMEOUT_S, false),
    HookSpec::new(EVENT_V2, "", HOOK_TIMEOUT_S, false),
];

/// The plugin's file in OpenCode's configuration directory: both versions
/// load every `.js` and `.ts` file in its `plugin/` and `plugins/` at start
/// (1.x `config/plugin.ts`; 2.x `core/src/plugin/source-directory.ts`).
const PLUGIN_FILE: &str = "plugins/openmoat.js";

/// OpenMoat's plugin, which is OpenCode's hook file: `moat init` writes it to
/// `<config dir>/plugins/openmoat.js` with the binary's path filled in.
static PLUGIN: OwnedFile = OwnedFile {
    name: "OpenCode plugin",
    source: include_str!("opencode/integration/openmoat.js"),
    first_line: "// OpenMoat for OpenCode.",
};

/// OpenCode 1 reads a default export `{ id, server }` from 1.3.4 on
/// (`plugin/shared.ts`, `readV1Plugin`; 1.3.3 has none), OpenCode 2 reads
/// `{ id, setup }` (`core/src/plugin/module.ts`).
const VERSIONS: HookVersions = HookVersions {
    program: "opencode",
    oldest: (1, 3, 4),
    older: "OpenCode before 1.3.4 loads a plugin only from a function export, and \
         OpenMoat's plugin is an object that serves OpenCode 1 and 2; upgrade OpenCode",
    hooks: &[
        ((1, 3, 4), "OpenCode 1's `tool.execute.before`"),
        ((2, 0, 0), "OpenCode 2's `execute.before`"),
    ],
};

/// OpenCode 2 can ask; OpenCode 1 cannot, so there an `ask` is a deny that
/// says how to approve it.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "opencode",
    display_name: "OpenCode",
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("OpenCode 1 gives plugins no way to ask the person"),
        defer_is_ask_on_no_ask: false,
        ..Asks::BASE
    },
    on_hook_failure: "blocks the call when OpenMoat's plugin throws (OpenCode's \
         `tool.execute.before` and `execute.before` fail closed), and the plugin blocks \
         when `openmoat` is missing, crashes or does not answer within 45 s; runs the call \
         unchecked when OpenCode does not load the plugin (OpenCode 1's `--pure` or \
         `OPENCODE_PURE`, OpenCode 2's `-openmoat` in `plugins`, or an error loading it)",
    gaps: "no OS sandbox from OpenMoat; OpenCode 1 plugins cannot ask, so an ask is a \
         deny that says how to approve it; OpenCode before 1.3.4 is not supported; other \
         plugins and custom tools run in OpenCode's process with the agent's rights, and \
         a project's load at start with no prompt; a project's `-openmoat` turns \
         OpenMoat off in OpenCode 2; OpenCode 2's `--auto` approves OpenMoat's asks; the \
         person's `!` shell commands are not checked; calls run unchecked if OpenCode \
         does not load the plugin (`--pure`, `OPENCODE_PURE`, a load error; `openmoat \
         status` and `doctor` say when it has not reported loading since it or OpenCode \
         changed); a failed or slow hook blocks the call",
    // `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode` (1.x
    // `packages/core/src/global.ts`; 2.x `util/src/global-roots.ts`), or
    // `OPENCODE_CONFIG_DIR`, which OpenCode 1 reads as well and OpenCode 2
    // instead (`location.rs`).
    install: Some(InstallSpec {
        dir_variable: location::VARIABLE,
        dir_name: location::DIR_NAME,
        config_file: PLUGIN_FILE,
        hooks: HOOKS,
        hook_file: HookLayout::Owned(&PLUGIN),
        location: Location::Custom(&location::LOCATE),
        versions: Some(VERSIONS),
        // a further configuration directory, read like this one with its own
        // plugins, tools and configuration files: `OPENCODE_CONFIG_DIR` (1.x
        // `config/paths.ts`), and the XDG one OpenCode 1 still reads when that
        // variable moves the directory OpenMoat's plugin is in
        also_dirs: &[
            AlsoDir::Variable(location::CONFIG_DIR),
            AlsoDir::Below(location::VARIABLE, location::APP),
        ],
        // OpenCode 1 loads its plugins for a project when it first serves one
        // and logs a plugin that fails and skips it (`plugin/index.ts`,
        // `Plugin.state`); the plugin reports loading from `server` and from
        // OpenCode 2's `setup` alike. Its sessions live in a database in its
        // data directory that commands loading no plugin write too, so no
        // activity tells a run that should have loaded it.
        heartbeat: Some(Heartbeat {
            program: "opencode",
            activity: &[],
        }),
        ..InstallSpec::BASE
    }),
    // `mcp.<name>` (1.x) and `mcp.servers.<name>` (2.x) in the configuration
    // files OpenCode merges: the global `config.json` (1.x), `opencode.json`
    // and `opencode.jsonc`, and a project's `opencode.json[c]` and
    // `.opencode/opencode.json[c]` (1.x `config/config.ts`; 2.x
    // `core/src/config.ts`, `config/normalize.ts`).
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
    // A project's `opencode.json[c]` and `.opencode/opencode.json[c]` add
    // plugins, MCP servers and permission rules, and its `.opencode/plugins/`
    // and `.opencode/plugin/` load in OpenCode's process at start, with no
    // prompt. In OpenCode 2 a `-openmoat` (or `-*`) entry in `plugins`, or a
    // policy denying OpenMoat's plugin, turns it off: in a project's file the
    // warning says so, in the person's own the agent is not protected
    // (`project_settings.rs`). Writes to these files ask (`runs-later`).
    project_settings: Some(ProjectSettingsSpec {
        dir: "",
        shared: "opencode.json",
        local: Some(".opencode/opencode.json"),
        more: &["opencode.jsonc", ".opencode/opencode.jsonc"],
        hook_dir: Some(HookDir {
            path: ".opencode/plugins",
            also: &[".opencode/plugin"],
            extensions: &["js", "ts"],
        }),
        reader: &project_settings::READER,
        user_file: "opencode.json",
        // OpenCode 2 reads these two; OpenCode 1's `config.json` cannot remove a plugin.
        user_more: &["opencode.jsonc"],
    }),
    protect: protect::PROTECT,
    process: protect::PROCESS,
    advisories: advisories::ADVISORIES,
    docs: doc::DOCS,
    ..HostSpec::BASE
};

/// What OpenMoat's plugin sends from either version's hook.
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
            Some(EVENT) => parse(host, Api::V1, payload),
            Some(EVENT_V2) => parse(host, Api::V2, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn event_of(&self, event: &str) -> HookEvent {
        hook_event(if event == EVENT_V2 { Api::V2 } else { Api::V1 })
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        render(decision)
    }

    fn bench_payload(&self, call: &BenchCall, at: &Place<'_>) -> Option<String> {
        bench::payload(call, at)
    }

    fn read_reply(&self, _call: &BenchCall, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit)
    }

    fn seen(&self, _call: &BenchCall, verdict: Verdict) -> Answer {
        bench::seen(verdict)
    }
}

/// Which plugin API sent a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Api {
    /// OpenCode 1's `tool.execute.before`.
    V1,
    /// OpenCode 2's `execute.before`.
    V2,
}

/// OpenCode 2 can put an `ask` to the person; OpenCode 1 cannot.
fn hook_event(api: Api) -> HookEvent {
    match api {
        Api::V1 => HookEvent::PreToolUseNoAsk,
        Api::V2 => HookEvent::PreToolUse,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    tool: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    input: Value,
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
    pub api: Api,
    pub tool: &'a str,
    pub args: &'a Value,
    pub cwd: Option<&'a str>,
    pub mcp_servers: &'a [String],
    pub windows: bool,
}

fn parse(host: Host, api: Api, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let event = match api {
        Api::V1 => EVENT,
        Api::V2 => EVENT_V2,
    };
    if p.tool.is_empty() {
        return Err(HostError::MissingField {
            tool: event.to_owned(),
            field: "tool",
        });
    }
    // OpenCode 1 hands a tool `args`, OpenCode 2 `input`.
    let args = match api {
        Api::V1 => &p.args,
        Api::V2 => &p.input,
    };
    let cwd = p.directory.filter(|c| !c.is_empty());
    let call = Call {
        api,
        tool: &p.tool,
        args,
        cwd: cwd.as_deref(),
        mcp_servers: &p.mcp_servers,
        // OpenCode runs on the machine `openmoat guard` runs on, so a guard
        // built for Windows reads every call as Windows'; the plugin's
        // `platform` also says so, which lets tests read Windows payloads
        // elsewhere. A payload's word never makes a Windows path relative.
        windows: cfg!(windows) || p.platform.as_deref() == Some("win32"),
    };
    let action = tools::map(&call)?;
    // `write` replaces the whole file with `content`.
    let content = match (p.tool.as_str(), &action) {
        ("write", Some(Action::FsWrite { .. })) => {
            args.get("content").and_then(Value::as_str).map(str::to_owned)
        }
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
        event: hook_event(api),
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
