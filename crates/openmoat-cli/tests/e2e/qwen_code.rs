//! Qwen Code end to end: `init` adds one named `PreToolUse` entry to
//! `settings.json`, `guard --host qwen-code` answers in Claude Code's format,
//! and the person's settings stay. What every host does is in `hosts/`.
//!
//! The payloads follow Qwen Code's documentation and source
//! (`crates/openmoat-hosts/src/host/qwen_code/fixtures/README.md`); none is
//! captured from a running `qwen`.

use std::fs;
use std::path::PathBuf;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, stdout, text};

/// A settings file as a person keeps it, with a hook of their own.
pub(crate) const ORIGINAL: &str = "{\n  \"model\": { \"name\": \"qwen3-coder-plus\" },\n  \
     \"hooks\": { \"PreToolUse\": [ { \"matcher\": \"Bash\", \"hooks\": [ { \"type\": \
     \"command\", \"command\": \"./lint.sh\" } ] } ] }\n}\n";

fn dir() -> String {
    crate::hosts::dir_of(Host::QwenCode)
}

fn settings(sb: &Sandbox) -> PathBuf {
    sb.home.join(dir()).join("settings.json")
}

/// A `PreToolUse` payload for `tool` with `input`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    json!({
        "session_id": "qwen-1", "transcript_path": "/t.jsonl",
        "cwd": sb.project().to_string_lossy(), "hook_event_name": "PreToolUse",
        "permission_mode": "default", "tool_name": tool, "tool_input": input,
        "tool_use_id": "call-1",
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("qwen-code", payload);
    let reply = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
    (out.status.code(), reply)
}

#[test]
fn init_adds_one_named_entry_beside_the_persons_and_is_idempotent() {
    let sb = Sandbox::bare(&[&dir()]);
    fs::write(settings(&sb), ORIGINAL).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let first = fs::read_to_string(settings(&sb)).unwrap();
    let root: Value = serde_json::from_str(&first).unwrap();
    let entries = root["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{root}");
    let ours = &entries[1];
    assert_eq!(ours["matcher"], "*", "{root}");
    assert_eq!(ours["hooks"][0]["name"], "openmoat", "{root}");
    assert_eq!(ours["hooks"][0]["timeout"], 600, "{root}");
    assert_eq!(root["model"]["name"], "qwen3-coder-plus");
    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert_eq!(fs::read_to_string(settings(&sb)).unwrap(), first);
}

#[test]
fn a_secret_read_is_denied_a_review_asks_and_a_defer_is_silent() {
    let sb = Sandbox::installed(&[&dir()]);
    let secret = sb.home.join(".aws").join("credentials");
    let (code, reply) = guard(
        &sb,
        &payload(
            &sb,
            "read_file",
            &json!({ "file_path": secret.to_string_lossy() }),
        ),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = reply["hookSpecificOutput"]["permissionDecisionReason"].to_string();
    assert!(reason.contains("secrets-paths"), "{reply}");

    // An ungoverned tool is left to Qwen Code's own flow: nothing printed.
    let (code, reply) = guard(&sb, &payload(&sb, "todo_write", &json!({ "todos": [] })));
    assert_eq!((code, reply), (Some(OK), Value::Null));
}

#[test]
fn a_review_reaches_qwen_code_as_ask() {
    let sb = Sandbox::installed_with_review(&[&dir()]);
    // Outside the project, so no rule matches and the catch-all `review` applies
    // (a write in the project is `project-fs`'s allow).
    let file = sb.home.join("notes.txt");
    let (code, reply) = guard(
        &sb,
        &payload(
            &sb,
            "write_file",
            &json!({ "file_path": file.to_string_lossy(), "content": "x" }),
        ),
    );
    assert_eq!(code, Some(OK), "{reply}");
    assert_eq!(
        reply["hookSpecificOutput"]["permissionDecision"], "ask",
        "{reply}"
    );
}
