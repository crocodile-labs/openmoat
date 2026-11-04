//! goose: `init` writes OpenMoat's plugin with one fail-closed `PreToolUse`
//! entry; goose cannot prompt, so a review arrives as a block; a deferred call is
//! left to goose; `uninstall` takes the entry out. What every host does is in
//! `hosts/`.

use std::fs;
use std::path::PathBuf;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, stdout, text};

/// The goose configuration directory the sandbox's home holds.
fn dir() -> String {
    crate::hosts::dir_of(Host::Goose)
}

/// OpenMoat's plugin's hook file.
fn hook_file(sb: &Sandbox) -> PathBuf {
    sb.home
        .join(".agents")
        .join("plugins")
        .join("openmoat")
        .join("hooks")
        .join("hooks.json")
}

/// goose's `PreToolUse` payload of `tool` with `input`, run in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    json!({
        "event": "PreToolUse", "session_id": "goose-1", "matcher_context": tool,
        "tool_call_id": "call-1", "tool_name": tool, "tool_input": input,
        "working_dir": sb.project().to_string_lossy(),
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("goose", payload);
    let reply = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
    (out.status.code(), reply)
}

#[test]
fn init_writes_one_entry_that_blocks_when_the_hook_fails() {
    let sb = Sandbox::installed(&[&dir()]);
    let hook: Value = serde_json::from_str(&fs::read_to_string(hook_file(&sb)).unwrap()).unwrap();
    let entries = hook["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{hook}");
    let action = &entries[0]["hooks"][0];
    assert_eq!(action["on_failure"], "block", "{hook}");
    assert_eq!(action["type"], "command", "{hook}");
    assert!(entries[0].get("matcher").is_none(), "{hook}");
    assert!(
        action["command"]
            .as_str()
            .unwrap()
            .ends_with(" guard --host goose"),
        "{hook}"
    );
}

#[test]
fn a_secret_read_is_blocked_and_an_ask_arrives_as_a_block() {
    let sb = Sandbox::installed(&[&dir()]);
    let secret = sb.home.join(".aws").join("credentials");
    let (code, reply) = guard(
        &sb,
        &payload(&sb, "tree", &json!({ "path": secret.to_string_lossy() })),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "block", "{reply}");
    assert!(
        reply["reason"].as_str().unwrap().contains("secrets-paths"),
        "{reply}"
    );

    // Code Mode's script calls tools the hook never sees: a review, which goose
    // receives as a block saying how to approve it.
    let (code, reply) = guard(
        &sb,
        &payload(&sb, "execute_javascript", &json!({ "code": "1 + 1" })),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "block", "{reply}");
    assert!(
        reply["reason"].as_str().unwrap().contains("allow --last"),
        "{reply}"
    );
}

#[test]
fn a_deferred_call_is_left_to_goose_and_malformed_arguments_are_blocked() {
    let sb = Sandbox::installed(&[&dir()]);
    let file = sb.project().join("notes.txt");
    let out = sb.guard(
        "goose",
        &payload(
            &sb,
            "write",
            &json!({ "path": file.to_string_lossy(), "content": "x" }),
        ),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let reply = stdout(&out);
    assert!(
        reply.trim().is_empty() || reply.contains(r#""decision":"allow""#),
        "{reply}"
    );

    let (code, reply) = guard(&sb, &payload(&sb, "shell", &json!({ "command": "" })));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "block", "{reply}");
}

#[test]
fn uninstall_takes_the_entry_out() {
    let sb = Sandbox::installed(&[&dir()]);
    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let left = fs::read_to_string(hook_file(&sb)).unwrap_or_default();
    assert!(!left.contains("guard --host goose"), "{left}");
}
