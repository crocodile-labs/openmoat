//! `moat replay` and `moat report` over events produced by real `guard` calls.

use std::process::Stdio;

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, bash_payload, stdout, text};

/// An installed sandbox with two sessions of recorded decisions.
fn seeded() -> Sandbox {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let project = sb.project();
    for (session, command) in [
        ("alpha", "git status --short"),
        ("alpha", "npm install left-pad-pro"),
        ("alpha", "cat ~/.ssh/id_rsa"),
        ("beta", "cargo test"),
    ] {
        sb.guard("claude-code", &bash_payload(session, &project, command));
    }
    sb
}

#[test]
fn replay_groups_sessions_into_a_timeline() {
    let sb = seeded();
    let out = sb.moat(&["replay"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("alpha"), "{t}");
    assert!(t.contains("beta"), "{t}");
    assert!(t.contains(" UTC  alpha"), "{t}");
    assert!(t.contains("├─") && t.contains("└─"), "{t}");
    assert!(
        t.contains("✔") && t.contains("❓") && t.contains("⛔"),
        "{t}"
    );
    assert!(t.contains("secrets-paths"), "{t}");
    assert!(
        t.find("alpha").unwrap() < t.find("beta").unwrap(),
        "oldest session first"
    );
}

#[test]
fn replay_filters_by_session_host_and_window() {
    let sb = seeded();
    let one = text(&sb.moat(&["replay", "--session", "beta"]));
    assert!(
        one.contains("cargo test") && !one.contains("left-pad-pro"),
        "{one}"
    );

    let json: Value =
        serde_json::from_slice(&sb.moat(&["replay", "--format", "json"]).stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);
    assert_eq!(json[0]["session_id"], "alpha");
    assert_eq!(json[0]["events"].as_array().unwrap().len(), 3);

    let none = text(&sb.moat(&["replay", "--host", "cursor"]));
    assert!(none.contains("no sessions"), "{none}");

    let missing = sb.moat(&["replay", "--session", "nope"]);
    assert_eq!(missing.status.code(), Some(USAGE));
    let bad = sb.moat(&["replay", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(USAGE));
    assert!(text(&bad).contains("time window"));
}

#[test]
fn report_summarises_the_window() {
    let sb = seeded();
    let out = sb.moat(&["report"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("4 decisions"), "{t}");
    assert!(
        t.contains("2 allowed") && t.contains("1 asked") && t.contains("1 denied"),
        "{t}"
    );
    assert!(t.contains("secrets-paths") && t.contains("default"), "{t}");
    assert!(t.contains("claude-code"), "{t}");

    let json: Value = serde_json::from_slice(
        &sb.moat(&["report", "--format", "json", "--since", "today"])
            .stdout,
    )
    .unwrap();
    assert_eq!(json["total"], 4);
    assert_eq!(json["sessions"], 2);
    assert_eq!(json["by_host"]["claude-code"], 4);

    let empty = text(&sb.moat(&["report", "--host", "codex"]));
    assert!(empty.contains("0 decisions"), "{empty}");
}

#[test]
fn show_aligns_columns_and_stops_quietly_when_the_reader_does() {
    let sb = seeded();
    let table = stdout(&sb.moat(&["show"]));
    let lines: Vec<&str> = table.lines().collect();
    let host_column = |line: &str| line.find("claude-code").or_else(|| line.find("host"));
    assert!(lines.len() > 1, "{table}");
    assert!(
        lines
            .iter()
            .all(|l| host_column(l) == host_column(lines[0])),
        "{table}"
    );

    let mut child = sb
        .command()
        .arg("show")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(out.stderr.is_empty(), "{}", text(&out));
}
