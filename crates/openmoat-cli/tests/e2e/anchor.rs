//! `moat audit anchor` and `moat audit verify --against` (ADR-031): an anchor
//! holds while the log grows, and names itself once the newest events are gone.

use std::path::Path;
use std::process::Command;

use crate::common::{OK, Sandbox, USAGE, bash_payload, json, stderr, stdout, text};

/// Record `count` decisions, one after another.
fn decide(sb: &Sandbox, count: usize) {
    let project = sb.project();
    for i in 0..count {
        let out = sb.guard(
            "claude-code",
            &bash_payload("s1", &project, &format!("echo {i}")),
        );
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    }
}

fn anchor(sb: &Sandbox, args: &[&str]) -> String {
    let out = sb.moat_as_person(&[&["audit", "anchor"], args].concat());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    stdout(&out)
}

/// Delete every event after `id`: a valid, shorter chain.
fn truncate_after(sb: &Sandbox, id: i64) {
    openmoat_audit::testing::truncate_after(&sb.home.join(".moat/audit.db"), id).unwrap();
}

/// Anchor at event 2, grow the log, anchor at event 4: both hold. Delete event
/// 4 and after: the chain still verifies, and the second anchor names itself.
fn anchors_hold_until_truncated(sb: &Sandbox, place: &[&str], against: &Path) {
    decide(sb, 2);
    let first = anchor(sb, place);
    assert!(first.contains("anchored event 2"), "{first}");
    assert!(first.contains("nothing was"), "{first}");
    decide(sb, 2);
    let against = against.to_str().unwrap();
    let ok = sb.moat(&["audit", "verify", "--against", against]);
    assert_eq!(ok.status.code(), Some(OK), "{}", text(&ok));
    assert!(stdout(&ok).contains("1 anchor(s)"), "{}", text(&ok));

    anchor(sb, place);
    truncate_after(sb, 3);
    let doctor = sb.moat(&["doctor"]);
    assert!(
        stdout(&doctor).contains("hash chain intact"),
        "{}",
        text(&doctor)
    );
    assert!(
        stdout(&doctor).contains("audit anchor     last made"),
        "{}",
        text(&doctor)
    );

    let failed = sb.moat(&["audit", "verify", "--against", against]);
    assert_eq!(failed.status.code(), Some(USAGE), "{}", text(&failed));
    let shown = stdout(&failed);
    assert!(shown.contains("anchor 2 of 2 (event 4"), "{shown}");
    assert!(shown.contains("no longer in the log"), "{shown}");
    let report = json(&sb.moat(&["audit", "verify", "--against", against, "--format", "json"]));
    assert_eq!(report["failed"]["number"], 2);
    assert_eq!(report["failed"]["why"], "missing");
}

#[test]
fn a_file_anchor_names_itself_after_the_newest_events_are_deleted() {
    let sb = Sandbox::installed(&[".claude"]);
    let file = sb.home.join("anchors.jsonl");
    anchors_hold_until_truncated(&sb, &["--file", file.to_str().unwrap()], &file);
    let lines = std::fs::read_to_string(&file).unwrap();
    assert_eq!(lines.lines().count(), 2, "{lines}");
}

#[test]
fn a_git_anchor_is_a_commit_on_its_own_ref() {
    let sb = Sandbox::installed(&[".claude"]);
    let repo = sb.home.join("anchors-repo");
    std::fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    git(&["config", "user.name", "Pat"]);
    git(&["config", "user.email", "pat@example.com"]);
    anchors_hold_until_truncated(&sb, &["--git", repo.to_str().unwrap()], &repo);
    assert_eq!(git(&["rev-list", "--count", "refs/moat/anchors"]), "2");
    assert_eq!(
        git(&["for-each-ref", "refs/heads"]),
        "",
        "no branch was made"
    );
}

#[test]
fn anchoring_is_for_a_person_and_needs_a_place() {
    let sb = Sandbox::installed(&[".claude"]);
    decide(&sb, 1);
    let file = sb.home.join("anchors.jsonl");
    let file = file.to_str().unwrap();
    let scripted = sb.moat(&["audit", "anchor", "--file", file]);
    assert_eq!(scripted.status.code(), Some(USAGE), "{}", text(&scripted));
    assert!(
        stderr(&scripted).contains("must be run by a person"),
        "{}",
        text(&scripted)
    );
    let nowhere = sb.moat_as_person(&["audit", "anchor"]);
    assert_eq!(nowhere.status.code(), Some(USAGE), "{}", text(&nowhere));
    let missing = sb.moat(&["audit", "verify", "--against", file]);
    assert_eq!(missing.status.code(), Some(USAGE), "{}", text(&missing));
}
