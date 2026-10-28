//! A plugin's report that its host loaded it (ADR-042), end to end with pi's
//! extension: `guard --heartbeat` records it, and `status` and `doctor` tell
//! a plugin that has not loaded yet (a note, never an alarm on a fresh
//! `init`) from one the agent ran without (a warning, and not protected).

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, stderr, stdout, text};

const AGENT_DIR: &str = ".pi/agent";

fn status(sb: &Sandbox) -> Value {
    parse(&sb.moat(&["status", "--format", "json"]))
}

fn find<'a>(list: &'a Value, host: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["host"] == host)
        .unwrap_or_else(|| panic!("no {host} in {list}"))
}

fn heartbeat(sb: &Sandbox, host: &str) -> std::process::Output {
    sb.moat(&["guard", "--heartbeat", "--host", host])
}

/// Make `path` look written an hour ago, so a file written now is newer.
fn age(path: &Path) {
    let hour_ago = SystemTime::now() - Duration::from_hours(1);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(hour_ago)
        .unwrap();
}

/// A session pi wrote now, as `sessions/--<cwd>--/<file>.jsonl`.
fn session(sb: &Sandbox) {
    let dir = sb.home.join(AGENT_DIR).join("sessions/--proj--");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("2026-10-27_s.jsonl"), "{}\n").unwrap();
}

#[test]
fn a_fresh_init_is_not_loaded_yet_and_a_report_makes_it_loaded() {
    let sb = Sandbox::installed(&[AGENT_DIR]);
    let doc = status(&sb);
    assert_eq!(find(&doc["plugins"], "pi")["state"], "not-yet", "{doc}");
    // A note, not a problem: the agent has not run since.
    assert_eq!(find(&doc["agents"], "pi")["level"], "hook-only", "{doc}");
    let shown = text(&sb.moat(&["status"]));
    assert!(shown.contains("· plugin not loaded yet since"), "{shown}");

    let out = heartbeat(&sb, "pi");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "", "a report prints nothing");
    let record = fs::read_to_string(sb.home.join(".moat/loaded/pi.json")).unwrap();
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["host"], "pi");
    assert!(record["reported_ms"].is_i64(), "{record}");

    let doc = status(&sb);
    assert_eq!(find(&doc["plugins"], "pi")["state"], "reported", "{doc}");
    let checks = parse(&sb.moat(&["doctor", "--format", "json"]));
    assert!(
        checks["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["status"] == "note"
                && row["detail"]
                    .as_str()
                    .is_some_and(|d| d.starts_with("plugin loaded: last report or call"))),
        "{checks}"
    );
}

#[test]
fn a_session_written_without_a_report_is_not_protected_until_one_comes() {
    let sb = Sandbox::installed(&[AGENT_DIR]);
    age(&sb.home.join(AGENT_DIR).join("extensions/openmoat.js"));
    session(&sb);

    let doc = status(&sb);
    assert_eq!(find(&doc["plugins"], "pi")["state"], "missing", "{doc}");
    let agent = find(&doc["agents"], "pi");
    assert_eq!(agent["level"], "not-protected", "{doc}");
    assert!(
        agent["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("plugin not loaded since")),
        "{agent}"
    );
    let shown = text(&sb.moat(&["status"]));
    assert!(shown.contains("may run unchecked"), "{shown}");
    let checks = parse(&sb.moat(&["doctor", "--format", "json"]));
    assert!(
        checks["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["status"] == "warning"
                && row["name"] == "pi"
                && row["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains("may run unchecked"))),
        "{checks}"
    );

    assert_eq!(heartbeat(&sb, "pi").status.code(), Some(OK));
    let doc = status(&sb);
    assert_eq!(find(&doc["plugins"], "pi")["state"], "reported", "{doc}");
    assert_eq!(find(&doc["agents"], "pi")["level"], "hook-only", "{doc}");
}

/// A call the guard decided for the host came through the plugin: proof it
/// loaded, where its report cannot be written (inside `openmoat run`).
#[test]
fn a_call_the_guard_decided_counts_as_loaded() {
    let sb = Sandbox::installed(&[AGENT_DIR]);
    age(&sb.home.join(AGENT_DIR).join("extensions/openmoat.js"));
    session(&sb);
    let read = json!({ "path": sb.project().join("README.md") });
    let out = sb.guard("pi", &crate::pi::payload(&sb, "read", &read));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let doc = status(&sb);
    assert_eq!(find(&doc["plugins"], "pi")["state"], "reported", "{doc}");
}

#[test]
fn a_report_is_refused_for_a_hook_command_host_and_before_init() {
    let sb = Sandbox::installed(&[".codex"]);
    let out = heartbeat(&sb, "codex");
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(
        stderr(&out).contains("runs a hook command"),
        "{}",
        text(&out)
    );
    assert_eq!(stdout(&out), "");

    let bare = Sandbox::bare(&[AGENT_DIR]);
    let out = heartbeat(&bare, "pi");
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(!bare.home.join(".moat").exists(), "no state directory made");
}
