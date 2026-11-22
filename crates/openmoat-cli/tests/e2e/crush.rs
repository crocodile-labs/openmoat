//! Crush end to end: `init` adds one flat `PreToolUse` entry to its global
//! `crush.json` beside the person's, `guard --host crush` answers in Claude
//! Code's format, and a review arrives as a deny, since Crush cannot prompt.
//! What every host does is in `hosts/`.
//!
//! The payloads follow Crush's documentation and source
//! (`crates/openmoat-hosts/src/host/crush/fixtures/README.md`); none is
//! captured from a running `crush`.

use std::fs;
use std::path::PathBuf;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, stdout, text};

/// A `crush.json` as a person keeps it, with a hook of their own.
pub(crate) const ORIGINAL: &str = "{\n  \"options\": { \"debug\": false },\n  \"hooks\": { \
     \"PreToolUse\": [ { \"matcher\": \"^bash$\", \"command\": \"./check.sh\" } ] }\n}\n";

fn dir() -> String {
    crate::hosts::dir_of(Host::Crush)
}

fn config(sb: &Sandbox) -> PathBuf {
    sb.home.join(dir()).join("crush.json")
}

/// A `PreToolUse` payload for `tool` with `input`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    json!({
        "event": "PreToolUse", "hook_event_name": "PreToolUse", "session_id": "crush-1",
        "cwd": sb.project().to_string_lossy(), "tool_name": tool, "tool_input": input,
        "tool_use_id": "call-1",
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard(Host::Crush.id(), payload);
    let reply = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
    (out.status.code(), reply)
}

#[test]
fn init_adds_one_flat_entry_beside_the_persons_and_is_idempotent() {
    let sb = Sandbox::bare(&[&dir()]);
    fs::write(config(&sb), ORIGINAL).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let first = fs::read_to_string(config(&sb)).unwrap();
    let root: Value = serde_json::from_str(&first).unwrap();
    let entries = root["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{root}");
    assert_eq!(entries[0]["command"], "./check.sh", "{root}");
    let ours = &entries[1];
    assert_eq!(ours["name"], "openmoat", "{root}");
    assert_eq!(ours["timeout"], 600, "{root}");
    assert!(ours.get("matcher").is_none(), "{root}");
    assert!(
        ours["command"]
            .as_str()
            .unwrap()
            .ends_with(&sb.hook_args(Host::Crush.id())),
        "{root}"
    );
    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert_eq!(fs::read_to_string(config(&sb)).unwrap(), first);
}

#[test]
fn a_secret_read_is_denied_and_a_review_arrives_as_a_deny() {
    let sb = Sandbox::installed(&[&dir()]);
    let secret = sb.home.join(".aws").join("credentials");
    let (code, reply) = guard(
        &sb,
        &payload(
            &sb,
            "view",
            &json!({ "file_path": secret.to_string_lossy() }),
        ),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");

    // A subagent's calls fire no hook: starting one needs review, which Crush
    // cannot put to the person.
    let (code, reply) = guard(
        &sb,
        &payload(&sb, "agent", &json!({ "prompt": "look around" })),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    let reason = reply["hookSpecificOutput"]["permissionDecisionReason"].to_string();
    assert!(reason.contains("openmoat allow --last"), "{reply}");

    // An ungoverned tool is left to Crush: nothing printed.
    let (code, reply) = guard(&sb, &payload(&sb, "todos", &json!({ "todos": [] })));
    assert_eq!((code, reply), (Some(OK), Value::Null));
}
