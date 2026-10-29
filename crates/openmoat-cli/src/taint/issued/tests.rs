use openmoat_audit::NewEvent;
use openmoat_core::{Action, Decision};

use super::*;

/// A home whose policy makes reading `<project>/secret.txt` ask, an empty
/// audit log, and the project directory.
fn home() -> (tempfile::TempDir, Home, String) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    let project = dir.path().join("p");
    std::fs::create_dir_all(&project).unwrap();
    let project = context::path_string(&project);
    let policy = format!(
        "version: 1\ndefaults: {{ \"*\": allow }}\nask:\n  - {{ id: secrets-paths, fs.read: [\"{project}/secret.txt\"] }}\n"
    );
    std::fs::write(home.policy_path(), policy).unwrap();
    Store::open(&home.audit_path()).unwrap();
    (dir, home, project)
}

fn record(home: &Home, session: &str, row: (&str, Option<&Action>, &str, &str)) {
    let (tool, action, rule, cwd) = row;
    let store = Store::open_existing(&home.audit_path()).unwrap();
    let decision = Decision::single(Verdict::Allow, rule, "test");
    store
        .record(&NewEvent {
            host: Host::ClaudeCode.id(),
            session_id: session,
            call_id: None,
            cwd: Some(cwd),
            tool,
            action,
            decision: &decision,
            latency_us: 0,
        })
        .unwrap();
}

fn issued(home: &Home, session: &str, cwd: &str) {
    record(home, session, ("SessionStart", None, ISSUED_RULE, cwd));
}

fn read(home: &Home, session: &str, path: &str, cwd: &str) {
    let action = Action::FsRead {
        path: path.to_owned(),
    };
    record(home, session, ("Read", Some(&action), "secrets-paths", cwd));
}

#[test]
fn a_session_is_tainted_by_its_own_secret_read_only() {
    let (_dir, home, project) = home();
    issued(&home, "s-a", &project);
    issued(&home, "s-b", &project);
    let lookup = IssuedTaint::new(Home::at(home.root().to_path_buf()));
    assert!(lookup.taint("s-a").unwrap().secrets.is_empty());
    let before = lookup.version();
    read(&home, "s-a", &format!("{project}/secret.txt"), &project);
    assert_ne!(lookup.version(), before, "a new event changes the version");
    // Read on from where the last lookup got.
    assert_eq!(lookup.taint("s-a").unwrap().secrets.len(), 1);
    assert!(lookup.taint("s-b").unwrap().secrets.is_empty());
}

/// Without the row its credential was issued with, the proxy knows neither
/// the session's host nor its project: its requests are refused.
#[test]
fn a_session_without_an_issue_row_has_no_taint_to_trust() {
    let (_dir, home, project) = home();
    read(&home, "s-c", &format!("{project}/other.txt"), &project);
    let lookup = IssuedTaint::new(Home::at(home.root().to_path_buf()));
    let error = lookup.taint("s-c").unwrap_err();
    assert!(error.contains("no proxy credential was issued"), "{error}");
}
