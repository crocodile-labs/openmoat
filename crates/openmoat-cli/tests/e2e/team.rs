//! `moat audit report` over exports from two machines.

use std::path::PathBuf;

use crate::common::{OK, Sandbox, USAGE, bash_payload, json, stdout, text};

const INSTALL: &str = "npm install left-pad-pro";
const KEY: &str = "cat ~/.ssh/id_rsa";

/// A machine where `commands` ran in session `s1`; `approve` runs
/// `moat allow --last` after the first of them, as a person would.
fn machine(commands: &[&str], approve: bool) -> Sandbox {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let project = sb.project();
    for (n, command) in commands.iter().enumerate() {
        sb.guard("claude-code", &bash_payload("s1", &project, command));
        if approve && n == 0 {
            let out = sb.moat_as_person(&["allow", "--last"]);
            assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        }
    }
    sb
}

/// Export `sb`'s log into `dir` as `name`.
fn export_to(sb: &Sandbox, dir: &Sandbox, name: &str) -> PathBuf {
    let file = dir.home.join(name);
    std::fs::write(&file, stdout(&sb.moat(&["audit", "export"]))).unwrap();
    file
}

#[test]
fn team_report_aggregates_verified_exports() {
    let a = machine(&[INSTALL, INSTALL, KEY], true);
    let b = machine(&["cargo test", KEY], false);
    let a_file = export_to(&a, &a, "a.jsonl");
    let b_file = export_to(&b, &a, "b.jsonl");
    let (a_path, b_path) = (a_file.to_string_lossy(), b_file.to_string_lossy());

    // a.jsonl twice: overlapping exports count each event once.
    let out = a.moat(&["audit", "report", &a_path, &b_path, &a_path]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let t = stdout(&out);
    assert!(t.contains("5 decisions"), "{t}");
    assert!(t.contains("claude-code  2 · 1 · 2"), "{t}");
    assert!(t.contains("secrets-paths"), "{t}");
    assert!(t.contains(&format!("    2  {KEY}")), "{t}");
    assert!(
        t.contains(&format!("1 asks, 1 approvals  {INSTALL}  [default]")),
        "{t}"
    );

    let report = json(&a.moat(&["audit", "report", &a_path, &b_path, "--format", "json"]));
    assert_eq!(report["summary"]["total"], 5);
    assert_eq!(report["top_denies"][0]["action"], KEY);
    assert_eq!(report["false_positive_candidates"][0]["action"], INSTALL);
    assert_eq!(report["sources"].as_array().map(Vec::len), Some(2));
}

#[test]
fn team_report_refuses_an_export_that_does_not_verify() {
    let a = machine(&["cargo test", KEY], false);
    let file = export_to(&a, &a, "a.jsonl");
    let edited = std::fs::read_to_string(&file)
        .unwrap()
        .replacen("\"deny\"", "\"allow\"", 1);
    std::fs::write(&file, edited).unwrap();
    let out = a.moat(&["audit", "report", &file.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("a.jsonl: line 2 does not verify"),
        "{}",
        text(&out)
    );
}
