//! Injected-input fingerprints (ADR-057): kept per session, first source wins,
//! bounded per session, redacted, and a version-8 database opens.

use rusqlite::Connection;

use super::*;
use crate::store::injected_inputs::{MAX_PER_SESSION, MAX_ROWS};

fn row(fingerprint: &str, source: &str) -> NewInjected {
    NewInjected {
        fingerprint: fingerprint.to_owned(),
        source: source.to_owned(),
    }
}

#[test]
fn a_session_finds_only_its_own_fingerprints_with_their_first_source() {
    let store = Store::open_in_memory().unwrap();
    assert!(!store.has_injected_inputs("claude-code", "a").unwrap());
    let added = store
        .add_injected_inputs(
            "claude-code",
            "a",
            &[row("f1", "fetch one"), row("f2", "fetch one")],
        )
        .unwrap();
    assert_eq!(added, 2);
    // the same fingerprint again keeps its first source
    let again = store
        .add_injected_inputs("claude-code", "a", &[row("f1", "fetch two")])
        .unwrap();
    assert_eq!(again, 0);
    assert!(store.has_injected_inputs("claude-code", "a").unwrap());
    let source = |host, session, fp| store.injected_source(host, session, fp).unwrap();
    assert_eq!(
        source("claude-code", "a", "f1").as_deref(),
        Some("fetch one")
    );
    assert_eq!(source("claude-code", "b", "f1"), None);
    assert_eq!(source("codex", "a", "f1"), None);
    assert!(!store.has_injected_inputs("claude-code", "b").unwrap());
}

#[test]
fn a_session_keeps_at_most_its_bound() {
    let store = Store::open_in_memory().unwrap();
    let rows: Vec<NewInjected> = (0..MAX_PER_SESSION + 10)
        .map(|n| row(&format!("{n:032x}"), "fetch x"))
        .collect();
    let added = store
        .add_injected_inputs("claude-code", "a", &rows)
        .unwrap();
    assert_eq!(added, usize::try_from(MAX_PER_SESSION).unwrap());
    let more = store
        .add_injected_inputs("claude-code", "a", &[row("late", "fetch y")])
        .unwrap();
    assert_eq!(more, 0);
    assert_eq!(
        store.injected_source("claude-code", "a", "late").unwrap(),
        None
    );
    // another session has its own room
    assert_eq!(
        store
            .add_injected_inputs("claude-code", "b", &[row("late", "fetch y")])
            .unwrap(),
        1
    );
}

/// A session past its bound adds nothing; the table as a whole holds many
/// sessions' worth before it prunes the oldest rows.
const _: () = assert!(MAX_ROWS > MAX_PER_SESSION * 10);

#[test]
fn a_source_is_redacted_and_no_text_but_the_fingerprint_is_stored() {
    let token = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let store = Store::open_in_memory().unwrap();
    store
        .add_injected_inputs(
            "claude-code",
            "a",
            &[row("f1", &format!("fetch https://x.example/?t={token}"))],
        )
        .unwrap();
    let source = store
        .injected_source("claude-code", "a", "f1")
        .unwrap()
        .unwrap();
    assert!(!source.contains(&token), "{source}");
    let columns: Vec<String> = store
        .conn
        .prepare("SELECT name FROM pragma_table_info('injected_inputs')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        columns,
        ["id", "ts_ms", "host", "session_id", "fingerprint", "source"]
    );
}

/// A version-8 database (0.15.0) has neither the MCP flow table (version 9) nor
/// the fingerprints; a version-9 one has only the flow table. Either way a
/// read-only handle reads the fingerprints as empty and adds nothing, and the
/// first writable open adds what is missing, version 9's step first, without
/// touching the events or their chain.
#[test]
fn version_8_and_9_databases_are_migrated_to_injected_inputs() {
    for (version, tables_removed) in [
        (8, "DROP TABLE injected_inputs; DROP TABLE mcp_flow;"),
        (9, "DROP TABLE injected_inputs;"),
    ] {
        migrated_from(version, tables_removed);
    }
}

fn migrated_from(version: i64, tables_removed: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        let d = decision(Verdict::Allow, "dev-shell", "ok");
        let action = Action::Shell {
            command: "git status".into(),
        };
        store.record(&sample(&d, &action)).unwrap();
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch(&format!(
            "{tables_removed} PRAGMA user_version = {version};"
        ))
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    assert!(!old.has_injected_inputs("claude-code", "a").unwrap());
    assert_eq!(
        old.add_injected_inputs("claude-code", "a", &[row("f", "s")])
            .unwrap(),
        0
    );
    drop(old);

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken, report.head), (1, None, head));
    store
        .add_injected_inputs("claude-code", "a", &[row("f", "s")])
        .unwrap();
    assert!(store.has_injected_inputs("claude-code", "a").unwrap());
    let tables: Vec<String> = store
        .conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        tables.iter().any(|t| t == "mcp_flow"),
        "from {version}: {tables:?}"
    );
    assert_eq!(
        schema::version(&store.conn).unwrap(),
        schema::SCHEMA_VERSION
    );
}
