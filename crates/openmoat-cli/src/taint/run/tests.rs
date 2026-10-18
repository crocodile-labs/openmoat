use openmoat_core::{Action, EvalContext, Policy};

use super::*;

const POLICY: &str = "version: 1\ndefaults: { \"*\": allow }\nask:\n  - { id: secrets-paths, fs.read: [\"/p/secret.txt\"] }\n";

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".to_owned(),
        case_insensitive_paths: false,
    }
}

/// A home with an empty audit log.
fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    Store::open(&home.audit_path()).unwrap();
    (dir, home)
}

fn read_secret(store: &Store, session: &str) {
    let action = Action::FsRead {
        path: "/p/secret.txt".to_owned(),
    };
    let decision = Decision::new(Verdict::Allow);
    store
        .record(&NewEvent {
            host: Host::ClaudeCode.id(),
            session_id: session,
            call_id: None,
            cwd: Some("/p"),
            tool: "Read",
            action: Some(&action),
            decision: &decision,
            latency_us: 0,
        })
        .unwrap();
}

#[test]
fn only_a_run_session_id_is_taken_from_the_environment() {
    assert_eq!(
        run_session(Some("run-1760000000000-ab12")),
        Some("run-1760000000000-ab12")
    );
    for bad in ["", "run-", "proxy-1", "run-a b", "run-a:b", "run-a/../b"] {
        assert_eq!(run_session(Some(bad)), None, "{bad:?}");
    }
    assert_eq!(run_session(None), None);
}

#[test]
fn a_session_is_linked_to_its_run_once() {
    let (_dir, home) = home();
    let store = Store::open_existing(&home.audit_path()).unwrap();
    link(&store, "run-1", Host::ClaudeCode, "s1").unwrap();
    link(&store, "run-1", Host::ClaudeCode, "s1").unwrap();
    let rows = store.session_after("run-1", EventId(0)).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].host.as_str(),
            rows[0].tool.as_str(),
            rows[0].call_id.as_deref()
        ),
        (LINK_HOST, "claude-code", Some("s1"))
    );
}

#[test]
fn the_run_is_tainted_by_its_linked_sessions_only() {
    let (_dir, home) = home();
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let store = Store::open_existing(&home.audit_path()).unwrap();
    let lookup = RunTaint::new(
        Home::at(home.root().to_path_buf()),
        "run-1",
        &compiled,
        "/p",
    );
    // Another agent session, not under this run, reads the secret.
    read_secret(&store, "elsewhere");
    assert_eq!(lookup.taint("run-1").unwrap(), Taint::default());
    // The run's own agent session reads it after the first lookup.
    link(&store, "run-1", Host::ClaudeCode, "s1").unwrap();
    assert_eq!(lookup.taint("run-1").unwrap(), Taint::default());
    read_secret(&store, "s1");
    let taint = lookup.taint("run-1").unwrap();
    assert_eq!(taint.secrets.len(), 1, "{taint:?}");
    // It stays tainted: later lookups fold on from where they were.
    assert_eq!(lookup.taint("run-1").unwrap(), taint);
    // Another run's id is not this proxy's.
    assert!(lookup.taint("run-2").is_err());
}
