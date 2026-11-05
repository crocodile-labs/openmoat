//! The pieces of MCP tool results (ADR-058): found only for the session and
//! host that received them, by server; bounded by age and per session; and a
//! version-8 database opens and migrates.

use rusqlite::Connection;

use super::*;
use crate::store::mcp_flow::{MAX_AGE_MS, MAX_SESSION_ROWS};

fn hashes(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn rows(store: &Store) -> i64 {
    store
        .conn
        .query_row("SELECT COUNT(*) FROM mcp_flow", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn pieces_are_found_by_session_host_and_server() {
    let store = Store::open_in_memory().unwrap();
    store
        .add_mcp_flow("claude-code", "s1", "web", &hashes(&["aa", "bb"]))
        .unwrap();
    store
        .add_mcp_flow("claude-code", "s1", "github", &hashes(&["bb"]))
        .unwrap();
    store
        .add_mcp_flow("claude-code", "s2", "notes", &hashes(&["cc"]))
        .unwrap();
    let found = |host: &str, session: &str, pieces: &[&str]| {
        store
            .mcp_flow_sources(host, session, &hashes(pieces))
            .unwrap()
    };
    assert_eq!(found("claude-code", "s1", &["aa"]), ["web"]);
    assert_eq!(found("claude-code", "s1", &["bb", "aa"]), ["github", "web"]);
    assert_eq!(
        found("claude-code", "s1", &["cc"]),
        Vec::<String>::new(),
        "another session's"
    );
    assert_eq!(
        found("codex", "s1", &["aa"]),
        Vec::<String>::new(),
        "another host's"
    );
    assert_eq!(found("claude-code", "s1", &[]), Vec::<String>::new());
    // the same piece again is one row
    store
        .add_mcp_flow("claude-code", "s1", "web", &hashes(&["aa"]))
        .unwrap();
    assert_eq!(rows(&store), 4);
}

#[test]
fn old_pieces_match_nothing_and_a_session_keeps_its_newest() {
    let store = Store::open_in_memory().unwrap();
    store
        .conn
        .execute(
            "INSERT INTO mcp_flow (ts_ms, host, session_id, server, piece)
             VALUES (?1, 'codex', 's1', 'web', 'old')",
            params![now_ms() - MAX_AGE_MS - 1],
        )
        .unwrap();
    assert_eq!(
        store
            .mcp_flow_sources("codex", "s1", &hashes(&["old"]))
            .unwrap(),
        Vec::<String>::new()
    );
    let many: Vec<String> = (0..=MAX_SESSION_ROWS).map(|i| format!("p{i}")).collect();
    store.add_mcp_flow("codex", "s1", "web", &many).unwrap();
    assert_eq!(
        rows(&store),
        MAX_SESSION_ROWS,
        "the old row and the oldest past the limit go"
    );
}

#[test]
fn known_secret_values_are_masked() {
    let token = format!("{}{}", "s3cr3t-", "x".repeat(24));
    let store = Store::open_in_memory()
        .unwrap()
        .with_secrets(KnownSecrets::new([token.as_str()]).unwrap());
    store
        .add_mcp_flow("codex", &token, "web", &hashes(&["aa"]))
        .unwrap();
    let stored: String = store
        .conn
        .query_row("SELECT session_id FROM mcp_flow", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.contains(&token), "{stored}");
    assert_eq!(
        store
            .mcp_flow_sources("codex", &token, &hashes(&["aa"]))
            .unwrap(),
        ["web"],
        "a lookup masks the same way"
    );
}

/// A version-8 database (0.15.x) has no pieces table: a read-only handle
/// finds nothing, and the first writable open adds the table without touching
/// the events or their chain.
#[test]
fn a_version_8_database_is_migrated_to_mcp_flow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        let d = decision(Verdict::Allow, "mcp", "ok");
        store
            .record(&sample(&d, &Action::mcp("mcp__gh__get_issue")))
            .unwrap();
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE mcp_flow; PRAGMA user_version = 8;")
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    assert_eq!(
        old.mcp_flow_sources("codex", "s1", &hashes(&["aa"]))
            .unwrap(),
        Vec::<String>::new()
    );
    old.add_mcp_flow("codex", "s1", "web", &hashes(&["aa"]))
        .unwrap();
    drop(old);
    let store = Store::open_existing(&path).unwrap();
    assert_eq!(store.verify_chain().unwrap().head, head);
    store
        .add_mcp_flow("codex", "s1", "web", &hashes(&["aa"]))
        .unwrap();
    assert_eq!(
        store
            .mcp_flow_sources("codex", "s1", &hashes(&["aa"]))
            .unwrap(),
        ["web"]
    );
}
