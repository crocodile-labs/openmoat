//! One row per host, in `Host::EVERY` order: what the shared suite
//! ([`super`]) needs to know about a host beyond its spec. A field left at
//! [`BASE`] means the case is covered for that host elsewhere, as the row's
//! comment says.

use serde_json::{Value, json};

use crate::common::{Sandbox, fixture};

/// A hook payload `moat guard` reads, built in a sandbox.
pub type Payload = fn(&Sandbox) -> String;

/// An edit of the installed hook file and a call that must then be denied.
pub struct Edit {
    pub change: fn(&str) -> String,
    pub call: Payload,
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
    /// A golden payload for a governed tool, under `tests/fixtures/hosts/`.
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
}

/// Every field at its "nothing here" value.
const BASE: Row = Row {
    id: "",
    hook: "",
    env: None,
    verdict_at: "",
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
};

/// The Claude Code and Codex `PreToolUse` reply.
const PRE_TOOL_USE: Row = Row {
    verdict_at: "/hookSpecificOutput/permissionDecision",
    reason_at: &["/hookSpecificOutput/permissionDecisionReason"],
    ..BASE
};

/// The `{decision, reason}` reply of OpenClaw's plugin, pi's extension and
/// Gemini CLI.
const DECISION: Row = Row {
    verdict_at: "/decision",
    reason_at: &["/reason"],
    ..BASE
};

pub fn rows() -> Vec<Row> {
    vec![
        // Uninstall: `uninstall.rs`; an edited hook file: `lock.rs`; a secret
        // read and an ask: `guard.rs`.
        Row {
            id: "claude-code",
            hook: "claude-code",
            governed: "claude-code/bash.json",
            unknown_tool: || pre_tool_use("FutureTool"),
            unknown_event: post_tool_use,
            ungoverned: &[|_| fixture("claude-code/ungoverned.json")],
            ..PRE_TOOL_USE
        },
        // Uninstall: `uninstall.rs`; an ask: `codex.rs`.
        Row {
            id: "codex",
            hook: "codex",
            governed: "codex/pretooluse-shell.json",
            unknown_tool: || pre_tool_use("future_tool"),
            unknown_event: post_tool_use,
            ..PRE_TOOL_USE
        },
        // Uninstall: `uninstall.rs`; an ask: `cursor.rs`.
        Row {
            id: "cursor",
            hook: "cursor",
            verdict_at: "/permission",
            reason_at: &["/user_message", "/agent_message"],
            governed: "cursor/preToolUse-write.json",
            unknown_tool: || {
                json!({"conversation_id": "s", "hook_event_name": "preToolUse",
                    "workspace_roots": ["/p"], "tool_name": "FutureTool",
                    "tool_input": {"file_path": "~/.ssh/id_rsa"}})
            },
            unknown_event: || json!({"hook_event_name": "afterFileEdit", "file_path": "/p/x"}),
            checks_unknown_tools: true,
            secret_read: Some(cursor_secret_read),
            benign: Some(|sb| {
                let file = sb.project().join("src/main.rs");
                let input = json!({"file_path": file.to_string_lossy(), "content": ""});
                cursor(sb, "Write", &input)
            }),
            ungoverned: &[|_| fixture("cursor/preToolUse-shell.json")],
            malformed: Some((
                |_| fixture("cursor/beforeMCPExecution-malformed.json"),
                Some("arguments cannot be checked"),
            )),
            ..BASE
        },
        // An ask: `continue_cli.rs`.
        Row {
            id: "continue",
            hook: "claude-code",
            env: Some("CONTINUE_PROJECT_DIR"),
            governed: "continue/pretooluse-bash.json",
            unknown_tool: || pre_tool_use("FutureTool"),
            unknown_event: post_tool_use,
            ..PRE_TOOL_USE
        },
        // OpenMoat's OpenClaw plugin: an unknown tool is `tool.unknown`,
        // checked for what its arguments name.
        Row {
            id: "openclaw",
            hook: "openclaw",
            persons_file: Some("{\n  \"gateway\": { \"port\": 18789 }\n}\n"),
            extra_dir: Some("openmoat"),
            governed: "openclaw/exec.json",
            unknown_tool: || {
                json!({"hook_event_name": "before_tool_call", "toolName": "future_tool",
                    "params": {"path": "~/.ssh/id_rsa"}, "sessionId": "s", "cwd": "/p"})
            },
            unknown_event: || {
                json!({"hook_event_name": "after_tool_call", "toolName": "exec",
                    "params": {"command": "ls"}})
            },
            checks_unknown_tools: true,
            secret_read: Some(|sb| {
                let secret = sb.home.join(".ssh/id_ed25519");
                crate::openclaw::payload(sb, "read", &json!({"path": secret}))
            }),
            benign: Some(|sb| {
                crate::openclaw::payload(sb, "exec", &json!({"command": "git status"}))
            }),
            ungoverned: &[
                |sb| {
                    crate::openclaw::payload(
                        sb,
                        "message",
                        &json!({"action": "reply", "text": "done"}),
                    )
                },
                |sb| crate::openclaw::payload(sb, "session_status", &json!({})),
            ],
            malformed: Some((
                |_| fixture("openclaw/read-malformed.json"),
                Some("cannot be checked"),
            )),
            ask: Some(|sb| {
                let outside = sb.home.join("notes/todo.txt");
                crate::openclaw::payload(sb, "read", &json!({"path": outside}))
            }),
            ..DECISION
        },
        // Copilot sends every tool; one it does not document is decided as an
        // MCP tool, its arguments checked as an unknown tool's.
        Row {
            id: "copilot-cli",
            hook: "copilot-cli",
            verdict_at: "/permissionDecision",
            reason_at: &["/permissionDecisionReason"],
            governed: "copilot-cli/bash.json",
            unknown_tool: || {
                json!({"sessionId": "s", "cwd": "/p", "toolName": "future_tool",
                    "toolArgs": json!({"path": "~/.ssh/id_rsa"}).to_string()})
            },
            unknown_event: || {
                json!({"hook_event_name": "postToolUse", "toolName": "bash",
                    "toolArgs": json!({"command": "ls"}).to_string()})
            },
            checks_unknown_tools: true,
            secret_read: Some(|sb| {
                let secret = sb.home.join(".aws").join("credentials");
                copilot(sb, "view", &json!({ "path": secret.to_string_lossy() }))
            }),
            benign: Some(|sb| copilot(sb, "bash", &json!({ "command": "cargo test" }))),
            ungoverned: &[|sb| copilot(sb, "report_intent", &json!({ "intent": "x" }))],
            malformed: Some((
                |sb| {
                    json!({"sessionId": "cp-1", "cwd": sb.project().to_string_lossy(),
                        "toolName": "bash", "toolArgs": "{\"command\": "})
                    .to_string()
                },
                Some("kernel-error"),
            )),
            owns_file: true,
            edited: Some(Edit {
                change: |hook| hook.replace("\"timeoutSec\": 600", "\"timeoutSec\": 1"),
                call: |sb| copilot(sb, "bash", &json!({ "command": "ls" })),
            }),
            ..BASE
        },
        // OpenMoat's pi extension: as OpenClaw's plugin; pi runs what OpenMoat
        // makes no decision on, so a secret path must never pass.
        Row {
            id: "pi",
            hook: "pi",
            governed: "pi/bash.json",
            unknown_tool: || {
                json!({"hook_event_name": "tool_call", "toolName": "future_tool",
                    "input": {"path": "~/.ssh/id_rsa"}, "sessionId": "s", "cwd": "/p"})
            },
            unknown_event: || {
                json!({"hook_event_name": "tool_result", "toolName": "bash",
                    "input": {"command": "ls"}})
            },
            checks_unknown_tools: true,
            secret_read: Some(|sb| {
                crate::pi::payload(sb, "read", &json!({"path": "@~/.ssh/id_ed25519"}))
            }),
            benign: Some(|sb| crate::pi::payload(sb, "bash", &json!({"command": "git status"}))),
            ungoverned: &[|sb| crate::pi::payload(sb, "codemode", &json!({"code": "1"}))],
            malformed: Some((|_| fixture("pi/read-malformed.json"), None)),
            ask: Some(|sb| {
                let outside = json!({"path": sb.home.join("notes/todo.txt")});
                crate::pi::payload(sb, "read", &outside)
            }),
            persons_file: Some("export default function (pi) {}\n"),
            owns_file: true,
            edited: Some(Edit {
                change: |hook| hook.replace("return await answer(", "return; await answer("),
                call: |sb| crate::pi::payload(sb, "bash", &json!({ "command": "git status" })),
            }),
            ..DECISION
        },
        // Gemini CLI: an unknown tool is `tool.unknown` too. An allowed call,
        // an ungoverned tool and an ask: `gemini_cli.rs`, which checks the
        // whole reply.
        Row {
            id: "gemini-cli",
            hook: "gemini-cli",
            governed: "gemini-cli/write_file.json",
            unknown_tool: || {
                json!({"session_id": "s", "cwd": "/p", "hook_event_name": "BeforeTool",
                    "tool_name": "future_tool", "tool_input": {"path": "~/.ssh/id_rsa"}})
            },
            unknown_event: || {
                json!({"session_id": "s", "cwd": "/p", "hook_event_name": "AfterTool",
                    "tool_name": "read_file", "tool_input": {"file_path": "/p/x"}})
            },
            checks_unknown_tools: true,
            secret_read: Some(|sb| {
                let secret = sb.home.join(".aws").join("credentials");
                let input = json!({ "file_path": secret.to_string_lossy() });
                crate::gemini_cli::payload(sb, "read_file", &input)
            }),
            malformed: Some((
                |_| fixture("gemini-cli/read_file-malformed.json"),
                Some("file_path"),
            )),
            persons_file: Some(crate::gemini_cli::ORIGINAL),
            edited: Some(Edit {
                change: |hook| {
                    let mut root: Value = serde_json::from_str(hook).unwrap();
                    root["hooksConfig"] = json!({ "disabled": ["openmoat"] });
                    root.to_string()
                },
                call: |sb| {
                    let file = sb.project().join("a.txt");
                    let input = json!({ "file_path": file.to_string_lossy(), "content": "" });
                    crate::gemini_cli::payload(sb, "write_file", &input)
                },
            }),
            ..DECISION
        },
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

/// A Cursor `preToolUse` call in the project.
fn cursor(sb: &Sandbox, tool: &str, input: &Value) -> String {
    let project = sb.project();
    json!({
        "conversation_id": "c", "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "tool_name": tool, "tool_input": input, "tool_use_id": "tu-9"
    })
    .to_string()
}

/// Cursor's `beforeReadFile` of a secret.
fn cursor_secret_read(sb: &Sandbox) -> String {
    json!({
        "conversation_id": "conv-42", "generation_id": "gen-9",
        "hook_event_name": "beforeReadFile", "cursor_version": "2.3.1",
        "workspace_roots": [sb.home.to_string_lossy()],
        "file_path": sb.home.join(".aws").join("credentials").to_string_lossy(),
        "content": "[default]", "attachments": []
    })
    .to_string()
}

/// A Copilot CLI `preToolUse` call in the project.
fn copilot(sb: &Sandbox, tool: &str, args: &Value) -> String {
    crate::copilot_cli::payload(&sb.project(), tool, args)
}
