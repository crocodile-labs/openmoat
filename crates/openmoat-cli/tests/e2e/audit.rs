//! The audit hash chain end to end: concurrent `guard` processes, `show` and
//! `doctor` after an edit.

use openmoat_hosts::Host;

use crate::common::{OK, Sandbox, USAGE, bash_payload, json, stdout, text};
use crate::hosts::dir_of;

/// The host every test here records through.
const HOST: Host = Host::ClaudeCode;

/// A sandbox with OpenMoat installed for [`HOST`].
fn installed() -> Sandbox {
    Sandbox::installed(&[&dir_of(HOST)])
}

/// Run `count` `guard` calls at once, as parallel tool calls do.
fn guard_concurrently(sb: &Sandbox, count: usize) {
    let project = sb.project();
    std::thread::scope(|scope| {
        let calls: Vec<_> = (0..count)
            .map(|i| {
                let payload = bash_payload("s1", &project, &format!("echo {i}"));
                scope.spawn(move || sb.guard(HOST.id(), &payload))
            })
            .collect();
        for call in calls {
            let out = call.join().unwrap();
            assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        }
    });
}

#[test]
fn concurrent_guards_build_one_chain_that_doctor_verifies() {
    let sb = installed();
    guard_concurrently(&sb, 12);
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("12 events, hash chain intact"),
        "{}",
        text(&doctor)
    );

    let shown = json(&sb.moat(&["show", "--session", "s1", "--format", "json"]));
    let events = shown.as_array().expect("an array of events");
    assert_eq!(events.len(), 12);
    assert_eq!(events[0]["prev_hash"], openmoat_audit::GENESIS);
    for pair in events.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
        assert_eq!(pair[1]["hash"].as_str().map(str::len), Some(64));
    }
}

#[test]
fn doctor_reports_an_edited_event_with_exit_64() {
    let sb = installed();
    guard_concurrently(&sb, 4);
    openmoat_audit::testing::tamper_with_event(
        &sb.home.join(".moat/audit.db"),
        3,
        "deny",
        r#"["secrets-paths"]"#,
    )
    .unwrap();

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("hash chain broken at event 3: its contents do not match"),
        "{}",
        text(&doctor)
    );
    // Recording continues after the edit; the break stays reported.
    guard_concurrently(&sb, 1);
    assert_eq!(sb.moat(&["doctor"]).status.code(), Some(USAGE));
}

/// `openmoat audit stats` over the calls just made: counted per agent, with
/// decision times and the agent's spec facts; an empty window says so; a bad
/// window is a usage error.
#[test]
fn audit_stats_counts_the_calls_of_the_window() {
    let host = openmoat_hosts::Host::ClaudeCode;
    let dir = crate::hosts::dir_of(host);
    let sb = Sandbox::installed(&[dir.as_str()]);
    guard_concurrently(&sb, 3);
    let project = sb.project();
    let (verdict, _) = sb.guard_bash("s2", &project, "cat ~/.ssh/id_rsa");
    assert_eq!(verdict, "deny");

    let out = sb.moat(&["audit", "stats", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let stats = json(&out);
    assert_eq!(stats["format"], "openmoat-stats-v1");
    let agent = &stats["agents"][0];
    assert_eq!(agent["host"], host.id());
    assert_eq!(agent["calls"], 4);
    assert_eq!(agent["verdicts"]["deny"], 1);
    assert_eq!(agent["per_100_calls"]["deny"], 25.0);
    assert!(agent["latency"]["p99_us"].is_u64(), "{agent:#}");
    assert!(agent["hook_failure"]["fails"].is_string(), "{agent:#}");
    assert_eq!(stats["overall"]["calls"], 4);

    let shown = sb.moat(&["audit", "stats"]);
    assert_eq!(shown.status.code(), Some(OK), "{}", text(&shown));
    assert!(
        stdout(&shown).contains(host.display_name()),
        "{}",
        text(&shown)
    );

    let future = sb.moat(&[
        "audit",
        "stats",
        "--since",
        "2999-01-01",
        "--until",
        "3000-01-01",
    ]);
    assert_eq!(future.status.code(), Some(OK), "{}", text(&future));
    assert!(
        stdout(&future).contains("no agent calls"),
        "{}",
        text(&future)
    );

    let bad = sb.moat(&["audit", "stats", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(USAGE), "{}", text(&bad));
}

/// ADR-101: an edit whose hashes were recomputed, as by someone who can write
/// the log but not read the audit key, still fails on the MACs.
#[test]
fn doctor_reports_a_rewrite_without_the_audit_key() {
    let sb = installed();
    guard_concurrently(&sb, 4);
    let db = sb.home.join(".moat/audit.db");
    openmoat_audit::testing::rewrite_without_key(&db, 2, "deny").unwrap();
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("hash chain broken at event 2: its audit-key MAC does not match"),
        "{}",
        text(&doctor)
    );
    let export = sb.moat(&["audit", "export"]);
    let file = sb.home.join("export.jsonl");
    std::fs::write(&file, stdout(&export)).unwrap();
    let verified = sb.moat(&["audit", "verify", file.to_str().unwrap()]);
    assert_eq!(verified.status.code(), Some(USAGE), "{}", text(&verified));
    assert!(
        stdout(&verified).contains("line 2 (event 2): its audit-key MAC does not match"),
        "{}",
        text(&verified)
    );
}

/// ADR-101: without its key, a log that holds keyed events takes no more:
/// the call is denied rather than recorded without a MAC, and no new key is made.
#[test]
fn a_deleted_audit_key_denies_every_call_and_doctor_says_why() {
    let sb = installed();
    guard_concurrently(&sb, 1);
    let key = sb.home.join(".moat/audit.key");
    std::fs::remove_file(&key).unwrap();
    let payload = bash_payload("s1", &sb.project(), "echo after");
    let out = sb.guard(HOST.id(), &payload);
    assert_eq!(
        out.status.code(),
        Some(crate::common::DENY),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("audit key"), "{}", text(&out));
    assert!(!key.exists(), "no new key over keyed events");
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("the audit key needed to check it is missing or unreadable"),
        "{}",
        text(&doctor)
    );
}
