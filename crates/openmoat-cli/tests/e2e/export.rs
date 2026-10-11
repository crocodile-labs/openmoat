//! `moat audit export` over events recorded by real `guard` calls.

use std::process::Output;

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, bash_payload, json, stdout, text};

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// An installed sandbox with three decisions in two sessions, one naming a token.
fn seeded() -> Sandbox {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    for (session, command) in [
        ("alpha", "git status --short".to_owned()),
        (
            "alpha",
            format!("curl -H 'Authorization: Bearer {TOKEN}' https://x.test"),
        ),
        ("beta", "cargo test".to_owned()),
    ] {
        sb.guard("claude-code", &bash_payload(session, &project, &command));
    }
    sb
}

/// Run `moat audit export` with `args` and parse every output line.
fn export(sb: &Sandbox, args: &[&str]) -> Vec<Value> {
    let out = sb.moat(&[&["audit", "export"], args].concat());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    stdout(&out)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
        .collect()
}

#[test]
fn export_writes_one_chained_redacted_line_per_event() {
    let sb = seeded();
    let lines = export(&sb, &[]);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["format"], "moat-audit-export-v1");
    assert_eq!(lines[0]["prev_hash"], openmoat_audit::GENESIS);
    for pair in lines.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
    }
    assert_eq!(lines[2]["action"]["shell"]["command"], "cargo test");
    let raw = stdout(&sb.moat(&["audit", "export"]));
    assert!(!raw.contains(TOKEN), "{raw}");
}

#[test]
fn export_filters_by_session_host_and_window() {
    let sb = seeded();
    let beta = export(&sb, &["--session", "beta"]);
    assert_eq!(beta.len(), 1);
    assert_eq!(beta[0]["session_id"], "beta");
    assert!(export(&sb, &["--host", "cursor"]).is_empty());
    assert_eq!(
        export(&sb, &["--since", "today", "--host", "claude-code"]).len(),
        3
    );
    let bad = sb.moat(&["audit", "export", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(USAGE), "{}", text(&bad));
}

/// Write `contents` to a file in the sandbox and run `moat audit verify` on it.
fn verify(sb: &Sandbox, contents: &str, args: &[&str]) -> Output {
    let file = sb.home.join("export.jsonl");
    std::fs::write(&file, contents).unwrap();
    let path = file.to_string_lossy();
    sb.moat(&[&["audit", "verify", path.as_ref()], args].concat())
}

/// The head hash `moat doctor` prints for the database.
fn doctor_head(sb: &Sandbox) -> String {
    let doctor = stdout(&sb.moat(&["doctor"]));
    let (_, rest) = doctor.split_once("head ").expect("doctor prints the head");
    rest[..64].to_owned()
}

#[test]
fn verify_checks_an_export_offline_and_anchors_its_head() {
    let sb = seeded();
    let export = stdout(&sb.moat(&["audit", "export"]));
    let head = doctor_head(&sb);

    let ok = verify(&sb, &export, &["--anchor", &head]);
    assert_eq!(ok.status.code(), Some(OK), "{}", text(&ok));
    let t = stdout(&ok);
    assert!(
        t.contains("3 events (ids 1–3), hash chain intact from the start"),
        "{t}"
    );
    assert!(
        t.contains(&format!("head {head}")) && t.contains("anchor found"),
        "{t}"
    );

    let report = json(&verify(&sb, &export, &["--format", "json"]));
    assert_eq!(report["head"], head.as_str());
    assert_eq!(report["broken"], Value::Null);

    let dropped = export.lines().take(2).collect::<Vec<_>>().join("\n");
    let truncated = verify(&sb, &dropped, &["--anchor", &head]);
    assert_eq!(truncated.status.code(), Some(USAGE), "{}", text(&truncated));
    assert!(stdout(&truncated).contains("is not in this export"));
}

#[test]
fn verify_without_an_anchor_says_so_and_can_be_required() {
    let sb = seeded();
    let export = stdout(&sb.moat(&["audit", "export"]));

    let plain = verify(&sb, &export, &[]);
    assert_eq!(plain.status.code(), Some(OK), "{}", text(&plain));
    assert!(
        stdout(&plain).contains("hash chain intact from the start of the log, not anchored"),
        "{}",
        text(&plain)
    );
    let report = json(&verify(&sb, &export, &["--format", "json"]));
    assert_eq!(report["anchor"], "not_anchored");

    let required = verify(&sb, &export, &["--require-anchor"]);
    assert_eq!(required.status.code(), Some(USAGE), "{}", text(&required));
    assert!(
        stdout(&required).contains("not anchored"),
        "{}",
        text(&required)
    );

    let head = doctor_head(&sb);
    let anchored = verify(&sb, &export, &["--require-anchor", "--anchor", &head]);
    assert_eq!(anchored.status.code(), Some(OK), "{}", text(&anchored));
}

#[test]
fn verify_names_the_edited_line() {
    let sb = seeded();
    let export = stdout(&sb.moat(&["audit", "export"]));
    let edited = export.replacen("git status --short", "git status --long", 1);
    assert_ne!(edited, export);
    let out = verify(&sb, &edited, &[]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        stdout(&out).contains("line 1 (event 1): its contents do not match its hash"),
        "{}",
        text(&out)
    );
    let missing = sb.moat(&["audit", "verify", "no-such-file.jsonl"]);
    assert_eq!(missing.status.code(), Some(USAGE), "{}", text(&missing));
}
