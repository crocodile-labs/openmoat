//! The hook's MCP call decisions (ADR-045): a row is taken once, only for the
//! arguments and tool it names, never after an hour, and a version-5 database
//! opens.

use rusqlite::Connection;

use super::*;
use crate::store::mcp_tickets::MAX_AGE_MS;

fn event(store: &Store, session: &str) -> EventId {
    let d = decision(Verdict::Allow, "mcp", "ok");
    let action = Action::mcp("mcp__gh__get_issue");
    let mut e = sample(&d, &action);
    e.session_id = session;
    store.record(&e).unwrap()
}

fn add(store: &Store, session: &str, tool: &str, sha: &str) -> EventId {
    let id = event(store, session);
    store
        .add_mcp_ticket(&NewTicket {
            event: id,
            host: "claude-code",
            session_id: session,
            call_id: Some("t1"),
            tool,
            arguments_sha256: sha,
            verdict: "ask",
        })
        .unwrap();
    id
}

fn rows(store: &Store) -> i64 {
    store
        .conn
        .query_row("SELECT COUNT(*) FROM mcp_tickets", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_decision_is_taken_once_for_its_arguments_and_tool() {
    let store = Store::open_in_memory().unwrap();
    let first = add(&store, "s1", "mcp__gh__get_issue", "aa");
    let second = add(&store, "s2", "mcp__gh__get_issue", "aa");
    add(&store, "s3", "mcp__gh__delete_repo", "bb");

    assert_eq!(
        store.take_mcp_ticket("cc", |_| true).unwrap(),
        None,
        "other arguments"
    );
    assert_eq!(
        store
            .take_mcp_ticket("bb", |t| t.tool == "mcp__gh__get_issue")
            .unwrap(),
        None,
        "the same arguments for another tool"
    );
    let taken = store
        .take_mcp_ticket("aa", |t| t.tool == "mcp__gh__get_issue")
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            taken.event_id,
            taken.session_id.as_str(),
            taken.call_id.as_deref()
        ),
        (first, "s1", Some("t1")),
        "the oldest first"
    );
    assert_eq!(
        (taken.host.as_str(), taken.verdict.as_str()),
        ("claude-code", "ask")
    );
    let taken = store.take_mcp_ticket("aa", |_| true).unwrap().unwrap();
    assert_eq!(taken.event_id, second);
    assert_eq!(
        store.take_mcp_ticket("aa", |_| true).unwrap(),
        None,
        "each is taken once"
    );
    assert_eq!(rows(&store), 1);
}

#[test]
fn a_decision_older_than_an_hour_lets_nothing_through() {
    let store = Store::open_in_memory().unwrap();
    let e = event(&store, "s1");
    store
        .conn
        .execute(
            "INSERT INTO mcp_tickets (event_id, ts_ms, host, session_id, tool, arguments_sha256, verdict)
             VALUES (?1, ?2, 'codex', 's1', 'mcp__gh__get_issue', 'aa', 'allow')",
            params![e.0, now_ms() - MAX_AGE_MS - 1],
        )
        .unwrap();
    assert_eq!(store.take_mcp_ticket("aa", |_| true).unwrap(), None);
    assert_eq!(rows(&store), 0, "and it is removed");
}

#[test]
fn known_secret_values_are_masked_in_decisions() {
    let token = format!("{}{}", "s3cr3t-", "x".repeat(24));
    let store = Store::open_in_memory()
        .unwrap()
        .with_secrets(KnownSecrets::new([token.as_str()]).unwrap());
    add(&store, &token, "mcp__gh__get_issue", "aa");
    let stored: String = store
        .conn
        .query_row("SELECT session_id FROM mcp_tickets", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.contains(&token), "{stored}");
}

/// A version-5 database (0.10.x) has no decisions table: a read-only handle
/// finds nothing, and the first writable open adds the table without touching
/// the events or their chain.
#[test]
fn a_version_5_database_is_migrated_to_mcp_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        event(&store, "a");
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE mcp_tickets; PRAGMA user_version = 5;")
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    assert_eq!(old.take_mcp_ticket("aa", |_| true).unwrap(), None);
    drop(old);
    let store = Store::open_existing(&path).unwrap();
    assert_eq!(store.verify_chain().unwrap().head, head);
    add(&store, "a", "mcp__gh__get_issue", "aa");
    assert!(store.take_mcp_ticket("aa", |_| true).unwrap().is_some());
}
