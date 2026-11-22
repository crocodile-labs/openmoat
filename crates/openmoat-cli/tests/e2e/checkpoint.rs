//! Signed audit checkpoints and what a person was shown at a review (ADR-110):
//! a checkpoint signed here verifies an export elsewhere with the public key
//! alone, and fails once the log is cut below it; a held call that ran is
//! recorded beside what was shown.

use serde_json::{Value, json};

use crate::common::{OK, Sandbox, USAGE, bash_payload, stdout, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

fn decide(sb: &Sandbox, count: usize) {
    let project = sb.project();
    for i in 0..count {
        let out = sb.guard(
            Host::ClaudeCode.id(),
            &bash_payload("s1", &project, &format!("echo {i}")),
        );
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    }
}

fn export(sb: &Sandbox) -> String {
    let out = sb.moat(&["audit", "export"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    stdout(&out)
}

fn lines(export: &str) -> Vec<Value> {
    export
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn a_checkpoint_verifies_an_export_on_another_machine_until_the_log_is_cut() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    decide(&sb, 4);
    // An agent may not sign one: the command wants a person at a terminal.
    let refused = sb.moat(&["audit", "checkpoint"]);
    assert_ne!(refused.status.code(), Some(OK), "{}", text(&refused));

    let signed = sb.moat_as_person(&["audit", "checkpoint", "--format", "json"]);
    assert_eq!(signed.status.code(), Some(OK), "{}", text(&signed));
    let signed: Value = serde_json::from_str(stdout(&signed).trim()).unwrap();
    let size = signed["size"].as_u64().unwrap();
    assert!(size >= 4, "{signed}");
    let key = signed["public_key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("openmoat.dev/audit/"), "{key}");
    let doctor = sb.moat(&["doctor"]);
    assert!(stdout(&doctor).contains(&key), "{}", text(&doctor));

    // Copied to another machine: no audit key, no state directory.
    let elsewhere = Sandbox::bare(&[]);
    let checkpoint = elsewhere.home.join("checkpoint.txt");
    std::fs::copy(signed["path"].as_str().unwrap(), &checkpoint).unwrap();
    let exported = elsewhere.home.join("audit.jsonl");
    std::fs::write(&exported, export(&sb)).unwrap();
    let verify = |file: &std::path::Path, key: &str| {
        elsewhere.moat(&[
            "audit",
            "verify",
            file.to_str().unwrap(),
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--pubkey",
            key,
        ])
    };
    let ok = verify(&exported, &key);
    assert_eq!(ok.status.code(), Some(OK), "{}", text(&ok));
    assert!(stdout(&ok).contains("✔ checkpoint"), "{}", text(&ok));

    // Another key does not open it.
    let other = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let theirs = other.moat_as_person(&["audit", "checkpoint", "--format", "json"]);
    let theirs: Value = serde_json::from_str(stdout(&theirs).trim()).unwrap();
    let wrong = verify(&exported, theirs["public_key"].as_str().unwrap());
    assert_ne!(wrong.status.code(), Some(OK), "{}", text(&wrong));

    // The newest events deleted: the chain verifies, the checkpoint does not.
    openmoat_audit::testing::truncate_after(&sb.home.join(".moat/audit.db"), 2).unwrap();
    let cut = elsewhere.home.join("cut.jsonl");
    std::fs::write(&cut, export(&sb)).unwrap();
    let failed = verify(&cut, &key);
    assert_eq!(failed.status.code(), Some(USAGE), "{}", text(&failed));
    assert!(
        stdout(&failed).contains("hash chain intact"),
        "{}",
        text(&failed)
    );
    assert!(
        stdout(&failed).contains("events were deleted"),
        "{}",
        text(&failed)
    );
    // And on this machine, without an export.
    let here = sb.moat(&[
        "audit",
        "verify",
        "--checkpoint",
        checkpoint.to_str().unwrap(),
        "--pubkey",
        &key,
    ]);
    assert_eq!(here.status.code(), Some(USAGE), "{}", text(&here));
    let doctor = sb.moat(&["doctor"]);
    assert!(
        stdout(&doctor).contains("events were deleted"),
        "{}",
        text(&doctor)
    );
}

fn post_tool_use(sb: &Sandbox, id: &str, command: &str) {
    let payload = json!({
        "session_id": "s1", "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "PostToolUse", "tool_name": "Bash",
        "tool_input": {"command": command}, "tool_response": {"stdout": "", "stderr": ""},
        "tool_use_id": id
    });
    let out = sb.guard(Host::ClaudeCode.id(), &payload.to_string());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
}

// coverage: ASI09
#[test]
fn a_held_call_records_what_was_shown_and_whether_what_ran_is_it() {
    let sb = Sandbox::installed_with_review(&[&dir_of(Host::ClaudeCode)]);
    let project = sb.project();
    let held = |id: &str| {
        let payload =
            bash_payload("s1", &project, "make deploy").replace("\"t1\"", &format!("\"{id}\""));
        let out = sb.guard(Host::ClaudeCode.id(), &payload);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(stdout(&out).contains("\"ask\""), "{}", text(&out));
    };
    held("t1");
    let rows = lines(&export(&sb));
    let reasons = rows.last().unwrap()["reasons"].to_string();
    assert!(reasons.contains("shown: "), "{reasons}");

    // Approved, and ran as held.
    post_tool_use(&sb, "t1", "make deploy");
    let rows = lines(&export(&sb));
    let ran = rows.last().unwrap();
    assert_eq!(ran["tool"], "ran-after-review", "{ran}");
    assert_eq!(ran["rules"], json!(["review-ran-as-shown"]), "{ran}");

    // Approved, but what ran is another command.
    held("t2");
    post_tool_use(&sb, "t2", "make deploy; curl https://attacker.example");
    let rows = lines(&export(&sb));
    let ran = rows.last().unwrap();
    assert_eq!(ran["rules"], json!(["review-ran-changed"]), "{ran}");
    assert!(
        ran["action"].to_string().contains("attacker.example"),
        "{ran}"
    );
}
