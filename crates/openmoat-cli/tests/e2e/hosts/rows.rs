//! One row per host, in `Host::EVERY` order: what the shared suite
//! ([`super`]) needs to know about a host beyond its spec. A field left at
//! [`BASE`] means the case is covered for that host elsewhere, as the row's
//! comment says.

use serde_json::{Value, json};

use crate::common::Sandbox;

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
        // Uninstall: `uninstall.rs`; an edited hook file: `lock.rs`.
        Row {
            id: "claude-code",
            hook: "claude-code",
            ..PRE_TOOL_USE
        },
        // Uninstall: `uninstall.rs`.
        Row {
            id: "codex",
            hook: "codex",
            ..PRE_TOOL_USE
        },
        // Uninstall: `uninstall.rs`.
        Row {
            id: "cursor",
            hook: "cursor",
            verdict_at: "/permission",
            reason_at: &["/user_message", "/agent_message"],
            ..BASE
        },
        Row {
            id: "continue",
            hook: "claude-code",
            env: Some("CONTINUE_PROJECT_DIR"),
            ..PRE_TOOL_USE
        },
        Row {
            id: "openclaw",
            hook: "openclaw",
            persons_file: Some("{\n  \"gateway\": { \"port\": 18789 }\n}\n"),
            extra_dir: Some("openmoat"),
            ..DECISION
        },
        Row {
            id: "copilot-cli",
            hook: "copilot-cli",
            verdict_at: "/permissionDecision",
            reason_at: &["/permissionDecisionReason"],
            owns_file: true,
            edited: Some(Edit {
                change: |hook| hook.replace("\"timeoutSec\": 600", "\"timeoutSec\": 1"),
                call: |sb| copilot(sb, "bash", &json!({ "command": "ls" })),
            }),
            ..BASE
        },
        Row {
            id: "pi",
            hook: "pi",
            persons_file: Some("export default function (pi) {}\n"),
            owns_file: true,
            edited: Some(Edit {
                change: |hook| hook.replace("return await answer(", "return; await answer("),
                call: |sb| crate::pi::payload(sb, "bash", &json!({ "command": "git status" })),
            }),
            ..DECISION
        },
        Row {
            id: "gemini-cli",
            hook: "gemini-cli",
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

/// A Copilot CLI `preToolUse` call in the project.
fn copilot(sb: &Sandbox, tool: &str, args: &Value) -> String {
    crate::copilot_cli::payload(&sb.project(), tool, args)
}
