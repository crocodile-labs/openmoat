//! One row per host, in `Host::EVERY` order: what the shared suite
//! ([`super`]) needs to know about a host beyond its spec. A field left at
//! [`BASE`] means the case is covered for that host elsewhere, as the
//! host's file in `rows/` says.

use serde_json::{Value, json};

use crate::common::Sandbox;

mod claude_code;
mod codex;
mod continue_cli;
mod copilot_cli;
mod cursor;
mod gemini_cli;
mod hermes;
mod openclaw;
mod opencode;
mod pi;

/// A hook payload `moat guard` reads, built in a sandbox.
pub type Payload = fn(&Sandbox) -> String;

/// An edit of the installed hook file and a call that must then be denied.
pub struct Edit {
    pub change: fn(&str) -> String,
    pub call: Payload,
}

/// MCP servers in the host's own file, pinned at `init`.
pub struct Mcp {
    /// The file, relative to the host's directory.
    pub file: &'static str,
    /// Its text, the first server run by the command given.
    pub servers: fn(&str) -> String,
    /// The first server's command, which the test changes.
    pub command: &'static str,
    /// The first server's name.
    pub server: &'static str,
    /// A tool of the first server, as the host names it.
    pub tool: &'static str,
    /// A tool of another server, which keeps running.
    pub other_tool: Option<&'static str>,
    /// What `init` says it pinned.
    pub pinned: &'static str,
    /// The host's call of an MCP tool.
    pub call: fn(&Sandbox, &str) -> String,
}

/// A setting in the host's own settings that turns every hook off.
pub struct HooksOff {
    /// The settings file, relative to the host's directory.
    pub file: &'static str,
    /// The file's text with the setting, from its text before.
    pub change: fn(&str) -> String,
    /// Whether the setting is there before `init` (which pins it as found).
    pub before_init: bool,
    /// What the reason `status` gives names.
    pub names: &'static str,
}

/// What the suite knows about one host.
pub struct Row {
    /// The host's id.
    pub id: &'static str,
    /// The `--host` of the hook the host runs.
    pub hook: &'static str,
    /// The variable the host sets for its hook (`cn` sets `CONTINUE_PROJECT_DIR`).
    pub env: Option<&'static str>,
    /// The JSON pointer of the verdict in the host's reply.
    pub verdict_at: &'static str,
    /// The verdict a reply means, for a host whose reply spells each verdict
    /// its own way (Hermes Agent's `decision: block`, `action: approve`);
    /// `None` reads [`Self::verdict_at`].
    pub read_verdict: Option<fn(&Value) -> &'static str>,
    /// The JSON pointers of the reason in the host's reply.
    pub reason_at: &'static [&'static str],
    /// A file of the person's where the hook goes, which `uninstall` gives back.
    pub persons_file: Option<&'static str>,
    /// Whether the hook file is OpenMoat's whole, so `uninstall` deletes it.
    pub owns_file: bool,
    /// A directory in the host's directory `init` creates beside the hook
    /// file and `uninstall` deletes.
    pub extra_dir: Option<&'static str>,
    /// An edit of the hook file the lock catches.
    pub edited: Option<Edit>,
    /// A golden payload for a governed tool, under its host's `fixtures/` folder.
    pub governed: &'static str,
    /// A payload for a tool OpenMoat does not know, naming a secret path.
    pub unknown_tool: fn() -> Value,
    /// A valid payload for an event the adapter does not handle.
    pub unknown_event: fn() -> Value,
    /// Whether the host sends every tool, so an unknown one is checked for
    /// what its arguments name instead of being left to the host.
    pub checks_unknown_tools: bool,
    /// A read of a secret file.
    pub secret_read: Option<Payload>,
    /// A call the default policy allows.
    pub benign: Option<Payload>,
    /// Calls of tools OpenMoat does not govern.
    pub ungoverned: &'static [Payload],
    /// A payload whose arguments cannot be checked, and what its reason says.
    pub malformed: Option<(Payload, Option<&'static str>)>,
    /// A call the policy asks about once its catch-all is `ask`.
    pub ask: Option<Payload>,
    /// MCP servers whose change holds back their tools.
    pub mcp: Option<Mcp>,
    /// A setting that turns OpenMoat's hook off.
    pub hooks_off: Option<HooksOff>,
}

/// Every field at its "nothing here" value.
const BASE: Row = Row {
    id: "",
    hook: "",
    env: None,
    verdict_at: "",
    read_verdict: None,
    reason_at: &[],
    persons_file: None,
    owns_file: false,
    extra_dir: None,
    edited: None,
    governed: "",
    unknown_tool: || Value::Null,
    unknown_event: || Value::Null,
    checks_unknown_tools: false,
    secret_read: None,
    benign: None,
    ungoverned: &[],
    malformed: None,
    ask: None,
    mcp: None,
    hooks_off: None,
};

/// The Claude Code and Codex `PreToolUse` reply.
const PRE_TOOL_USE: Row = Row {
    verdict_at: "/hookSpecificOutput/permissionDecision",
    reason_at: &["/hookSpecificOutput/permissionDecisionReason"],
    ..BASE
};

/// The `{decision, reason}` reply of OpenClaw's plugin, pi's extension,
/// Gemini CLI and OpenCode's plugin.
const DECISION: Row = Row {
    verdict_at: "/decision",
    reason_at: &["/reason"],
    ..BASE
};

pub fn rows() -> Vec<Row> {
    vec![
        claude_code::row(),
        codex::row(),
        cursor::row(),
        continue_cli::row(),
        openclaw::row(),
        copilot_cli::row(),
        pi::row(),
        gemini_cli::row(),
        opencode::row(),
        hermes::row(),
    ]
}

/// A Claude Code `PreToolUse` call of `tool` naming a secret path.
fn pre_tool_use(tool: &str) -> Value {
    json!({"session_id": "s", "cwd": "/p", "hook_event_name": "PreToolUse",
           "tool_name": tool, "tool_input": {"file_path": "~/.ssh/id_rsa"}})
}

/// A Claude Code `PostToolUse` call, an event OpenMoat does not handle.
fn post_tool_use() -> Value {
    json!({"session_id": "s", "hook_event_name": "PostToolUse",
           "tool_name": "Bash", "tool_input": {"command": "ls"}})
}
