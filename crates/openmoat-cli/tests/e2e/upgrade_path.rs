//! An upgrade from a release before the audit key (0.22.0), as a person who
//! used OpenMoat for a while finds it: an audit log at an older schema with a
//! long session in it, no `audit.key`, an older default policy with their own
//! rule, and a lock an older binary wrote. This build's entry points run
//! against it in a long session's order: a `PreToolUse` whose taint fold saves
//! part-way (the first writer, #837), a `PostToolUse`, another call, `status`,
//! `doctor`, `report`, `audit export` and `audit verify`, then `policy upgrade`.
//! Every call is decided and recorded, the key is made once, the chain
//! verifies, keyed events start after the old ones and the person's rule stays.

use std::path::{Path, PathBuf};

use openmoat_audit::testing::as_written_by;
use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::common::{OK, Sandbox, bash_payload, output, stdout, text, verdict};
use crate::hosts::dir_of;

const HOST: Host = Host::ClaudeCode;
/// What `openmoat init` wrote from 0.1.1 to 0.3.0, before it recorded a base.
const V0_3_0: &str = include_str!("../../src/upgrade/default-v0.3.0.yaml");
/// The release the older lock recorded.
const OLDER_RELEASE: &str = "0.21.0";
/// The session that runs on through the upgrade.
const SESSION: &str = "long";
/// Copies of the calls made before the upgrade: the long session then holds
/// more than one page of the taint fold (512 events), so the fold saves.
const REPEAT: usize = 200;
/// Debug builds save the fold this often (ms) instead of every 2 s.
const CHECKPOINT_ENV: &str = "MOAT_TEST_TAINT_CHECKPOINT_MS";
/// A rule of the person's own in the older policy, which an upgrade keeps.
const MY_RULE: &str = "  - id: my-rule\n    shell: [\"make deploy\"]\n";

fn state(sb: &Sandbox, name: &str) -> PathBuf {
    sb.home.join(".moat").join(name)
}

/// A home as a release before the audit key left it, with its log at schema
/// `version`; returns it and the number of events in its log.
fn older_home(version: i64) -> (Sandbox, i64) {
    let sb = Sandbox::installed(&[&dir_of(HOST)]);
    let proj = sb.project();
    for command in ["git status", "cargo test", "ls -la"] {
        let out = sb.guard(HOST.id(), &bash_payload(SESSION, &proj, command));
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    }
    sb.guard(HOST.id(), &bash_payload("other", &proj, "git log -1"));
    // The older default policy with the person's own rule, no recorded base,
    // re-pinned and the sandbox synced by the person.
    let mine = V0_3_0.replace("ask:\n", &format!("ask:\n{MY_RULE}"));
    assert_ne!(mine, V0_3_0);
    std::fs::write(state(&sb, "policy.yaml"), mine).unwrap();
    std::fs::remove_file(state(&sb, "policy.base.yaml")).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    // The lock an older binary wrote: its release and its bytes.
    let lock_path = state(&sb, "policy.lock");
    let mut lock: Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    lock["binary_version"] = Value::from(OLDER_RELEASE);
    lock["binary_sha256"] = Value::from("0".repeat(64));
    std::fs::write(&lock_path, lock.to_string()).unwrap();
    // The log as that release wrote it, and no key.
    let db = state(&sb, "audit.db");
    as_written_by(&db, version, REPEAT).unwrap();
    std::fs::remove_file(state(&sb, "audit.key")).unwrap();
    let old = openmoat_audit::Store::open_read_only(&db)
        .unwrap()
        .latest_id()
        .unwrap()
        .unwrap()
        .0;
    (sb, old)
}

/// A `PreToolUse` in the long session, its fold saving after every page.
fn pre_tool_use(sb: &Sandbox, proj: &Path, command: &str) {
    let mut guard = sb.command();
    guard
        .env(CHECKPOINT_ENV, "0")
        .args(["guard", "--host", HOST.id()]);
    let out = output(&mut guard, Some(&bash_payload(SESSION, proj, command)));
    assert_eq!(out.status.code(), Some(OK), "{command}: {}", text(&out));
    assert_ne!(verdict(&out), "deny", "{command}: {}", text(&out));
    assert!(!text(&out).contains("kernel-error"), "{}", text(&out));
}

fn post_tool_use(sb: &Sandbox, proj: &Path, command: &str) {
    let payload = json!({
        "session_id": SESSION, "cwd": proj.to_string_lossy(), "hook_event_name": "PostToolUse",
        "tool_name": "Bash", "tool_input": {"command": command},
        "tool_response": {"stdout": "ok\n", "stderr": "", "interrupted": false},
        "tool_use_id": "t2"
    });
    let out = sb.guard(HOST.id(), &payload.to_string());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", text(&out));
}

/// `doctor` sees `events` events, the newest `keyed` with the key's MAC.
fn doctor_sees(sb: &Sandbox, events: i64, keyed: i64) {
    let shown = text(&sb.moat(&["doctor"]));
    assert!(
        shown.contains(&format!("{events} events, hash chain intact")),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("{keyed} events carry the audit key's MAC")),
        "{shown}"
    );
    assert!(!shown.contains("audit key needed"), "{shown}");
}

fn upgrade_from(version: i64) {
    let (sb, old) = older_home(version);
    let proj = sb.project();
    let key = state(&sb, "audit.key");

    pre_tool_use(&sb, &proj, "cargo build");
    let made = std::fs::read(&key).expect("the first call after the upgrade makes the key");
    post_tool_use(&sb, &proj, "cargo build");
    pre_tool_use(&sb, &proj, "git diff");
    assert_eq!(std::fs::read(&key).unwrap(), made, "the key is made once");

    let status = sb.moat(&["status"]);
    assert!(
        text(&status).contains(&format!("the lock recorded {OLDER_RELEASE}")),
        "{}",
        text(&status)
    );
    doctor_sees(&sb, old + 2, 2);
    let report = sb.moat(&["report"]);
    assert_eq!(report.status.code(), Some(OK), "{}", text(&report));
    let export = sb.moat(&["audit", "export"]);
    assert_eq!(export.status.code(), Some(OK), "{}", text(&export));
    let file = sb.home.join("export.jsonl");
    std::fs::write(&file, stdout(&export)).unwrap();
    let verified = sb.moat(&["audit", "verify", file.to_str().unwrap()]);
    assert_eq!(verified.status.code(), Some(OK), "{}", text(&verified));

    // The person brings the policy up to date: their rule stays, and calls
    // go on being decided and recorded under the key made above. An older
    // default may hold more than this one: the widening is accepted here.
    let out = sb.moat_as_person(&["policy", "upgrade", "--yes", "--accept-widening"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let policy = std::fs::read_to_string(state(&sb, "policy.yaml")).unwrap();
    assert!(policy.contains(MY_RULE), "{policy}");
    pre_tool_use(&sb, &proj, "git status");
    doctor_sees(&sb, old + 3, 3);
    assert_eq!(std::fs::read(&key).unwrap(), made);
}

/// Schema 1: the first release's log, before the hash chain.
#[test]
fn an_upgrade_from_a_log_before_the_hash_chain() {
    upgrade_from(1);
}

/// Schema 7: before the `review` verdict replaced `ask` (0.14.0).
#[test]
fn an_upgrade_from_a_log_before_review() {
    upgrade_from(7);
}

/// Schema 11: the last release before the audit key, which a person upgrading
/// to 0.22.0 or later most often has.
#[test]
fn an_upgrade_from_the_last_log_before_the_audit_key() {
    upgrade_from(11);
}
