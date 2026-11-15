//! The keyed chain (ADR-100): what a rewrite without the audit key leaves, the
//! upgrade from version 11, and a handle without the key failing closed.

use openmoat_core::{Decision, Verdict};
use rusqlite::{Connection, params};

use super::*;

fn record(store: &Store, command: &str) -> Result<EventId, StoreError> {
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push("dev-shell".to_owned());
    decision.reasons.push("ok".to_owned());
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store.record(&NewEvent {
        host: "claude-code",
        session_id: "s1",
        call_id: None,
        cwd: Some("/p"),
        tool: "Bash",
        action: Some(&action),
        decision: &decision,
        latency_us: 900,
    })
}

fn keyed_log(n: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let store = Store::open(&path).unwrap().with_chain_key(key());
    for i in 0..n {
        record(&store, &format!("echo {i}")).unwrap();
    }
    (dir, path)
}

fn verify(path: &std::path::Path, key: Option<ChainKey>) -> ChainReport {
    let store = Store::open_read_only(path).unwrap();
    let store = match key {
        Some(key) => store.with_chain_key(key),
        None => store,
    };
    store.verify_chain().unwrap()
}

#[test]
fn every_event_carries_the_keys_mac_and_verifies_with_it() {
    let (_dir, path) = keyed_log(3);
    let report = verify(&path, Some(key()));
    assert_eq!((report.events, report.keyed, report.broken), (3, 3, None));
    assert_eq!(report.keyed_after, Some(EventId(0)));
}

#[test]
fn a_rewrite_without_the_key_is_detected_where_it_starts() {
    let (_dir, path) = keyed_log(4);
    let conn = Connection::open(&path).unwrap();
    conn.execute("UPDATE events SET verdict = 'deny' WHERE id = 2", [])
        .unwrap();
    rehash_from(&conn, 2).unwrap();
    drop(conn);
    // The hash chain alone holds again: that is all an unkeyed chain had.
    let text: String = Store::open_read_only(&path)
        .unwrap()
        .export(&ExportFilter::default())
        .unwrap()
        .iter()
        .map(|l| serde_json::to_string(l).unwrap() + "\n")
        .collect();
    let hashes = verify_export(&text, None);
    assert_eq!((hashes.events, hashes.broken), (4, None));
    let report = verify(&path, Some(key()));
    let expected = ChainBreak {
        id: EventId(2),
        kind: BreakKind::MacMismatch,
    };
    assert_eq!(report.broken, Some(expected));
    assert_eq!(report.keyed, 1);
}

#[test]
fn a_removed_mac_and_another_key_are_detected() {
    let (_dir, path) = keyed_log(3);
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE events SET mac = NULL WHERE id = 3", [])
        .unwrap();
    let report = verify(&path, Some(key()));
    assert_eq!(report.broken.unwrap().kind, BreakKind::MacMissing);
    let other = ChainKey::new([8; 32], EventId(0));
    let report = verify(&path, Some(other));
    let expected = ChainBreak {
        id: EventId(1),
        kind: BreakKind::MacMismatch,
    };
    assert_eq!(report.broken, Some(expected));
}

#[test]
fn moving_the_mark_does_not_pass_rewritten_events_off_as_older_than_the_key() {
    let (_dir, path) = keyed_log(3);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "UPDATE events SET mac = NULL;
             UPDATE meta SET value = 3 WHERE key = 'unkeyed_last_id';",
        )
        .unwrap();
    // The key keeps its own record of where keyed events start.
    let report = verify(&path, Some(key()));
    let expected = ChainBreak {
        id: EventId(1),
        kind: BreakKind::MacMissing,
    };
    assert_eq!(report.broken, Some(expected));
}

#[test]
fn without_the_key_nothing_is_recorded_and_verification_stops_at_the_first_keyed_event() {
    let (_dir, path) = keyed_log(2);
    let store = Store::open_existing(&path).unwrap();
    let refused = record(&store, "echo x").err().unwrap();
    assert!(matches!(refused, StoreError::KeyMissing), "{refused}");
    assert_eq!(store.count().unwrap(), 2, "nothing was written");
    assert!(store.has_keyed_events().unwrap());
    let report = verify(&path, None);
    let expected = ChainBreak {
        id: EventId(1),
        kind: BreakKind::KeyUnavailable,
    };
    assert_eq!(report.broken, Some(expected));
}

#[test]
fn an_event_past_the_mark_without_a_mac_is_refused_by_the_database() {
    // As a process of an older build, which opened the log before the
    // upgrade, would append one.
    let (_dir, path) = keyed_log(1);
    let refused = Connection::open(&path).unwrap().execute(
        "INSERT INTO events (id, ts_ms, host, session_id, tool, action, verdict, rules, reasons,
                             latency_us, prev_hash, hash)
         VALUES (2, 0, 'h', 's', 't', 'null', 'allow', '[]', '[]', 1, 'x', 'y')",
        [],
    );
    let error = refused.err().unwrap().to_string();
    assert!(error.contains("audit key"), "{error}");
}

#[test]
fn a_log_shorter_than_its_key_is_refused() {
    let (_dir, path) = keyed_log(1);
    let store = Store::open_existing(&path)
        .unwrap()
        .with_chain_key(ChainKey::new([9; 32], EventId(5)));
    let refused = record(&store, "echo x").err().unwrap();
    assert!(
        matches!(
            refused,
            StoreError::KeyAhead {
                newest: EventId(1),
                after: EventId(5)
            }
        ),
        "{refused}"
    );
}

/// Put the log at `path` back as version 11 left it: no `mac`, no mark, no
/// trigger.
fn put_back_version_11(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER events_keyed;
         ALTER TABLE events DROP COLUMN mac;
         DELETE FROM meta WHERE key = 'unkeyed_last_id';
         PRAGMA user_version = 11;",
    )
    .unwrap();
}

#[test]
fn a_version_11_log_with_events_keeps_them_under_the_unkeyed_chain_and_keys_new_ones() {
    let (_dir, path) = keyed_log(2);
    put_back_version_11(&path);

    // Read-only, as `openmoat show` before any writer ran: nothing is keyed,
    // with or without a key.
    let old = verify(&path, None);
    assert_eq!((old.events, old.keyed, old.broken), (2, 0, None));
    assert_eq!(old.keyed_after, None);
    let exported = Store::open_read_only(&path)
        .unwrap()
        .export(&ExportFilter::default())
        .unwrap();
    assert!(exported.iter().all(|l| l.format == ExportFormat::V1));

    // The first writer migrates, finds no keyed event and makes the key after
    // the newest event, as the CLI does.
    let store = Store::open_existing(&path).unwrap();
    assert!(!store.has_keyed_events().unwrap());
    let store = upgraded(store);
    record(&store, "echo new").unwrap();
    drop(store);
    let mark: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT value FROM meta WHERE key = 'unkeyed_last_id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mark, 2);

    let with_key = ChainKey::new([9; 32], EventId(2));
    let report = verify(&path, Some(with_key));
    assert_eq!((report.events, report.keyed, report.broken), (3, 1, None));
    assert_eq!(report.keyed_after, Some(EventId(2)));
    // Without the key, the two old events still verify and the new one stops it.
    let report = verify(&path, None);
    let expected = ChainBreak {
        id: EventId(3),
        kind: BreakKind::KeyUnavailable,
    };
    assert_eq!((report.events, report.broken), (3, Some(expected)));
}

#[test]
fn an_export_is_checked_with_the_key_that_made_it_and_by_hashes_elsewhere() {
    let store = Store::open_in_memory().unwrap().with_chain_key(key());
    for i in 0..3 {
        record(&store, &format!("echo {i}")).unwrap();
    }
    let lines = store.export(&ExportFilter::default()).unwrap();
    let text = |lines: &[ExportedEvent]| -> String {
        lines
            .iter()
            .map(|l| serde_json::to_string(l).unwrap() + "\n")
            .collect()
    };
    let whole = text(&lines);

    let mine = verify_export_keyed(&whole, None, Some(&key()));
    assert_eq!((mine.events, mine.keyed, mine.keyed_unchecked), (3, 3, 0));
    let elsewhere = verify_export(&whole, None);
    assert_eq!(elsewhere.broken, None);
    assert_eq!((elsewhere.keyed, elsewhere.keyed_unchecked), (0, 3));
    let other = ChainKey::new([8; 32], EventId(0));
    let not_mine = verify_export_keyed(&whole, None, Some(&other));
    assert_eq!((not_mine.broken, not_mine.keyed_unchecked), (None, 3));

    // A line rewritten with its hash recomputed: only the key shows it.
    let mut forged = lines.clone();
    forged[1].verdict = "deny".to_owned();
    forged[1].hash = forged[1].fields().hash();
    forged[2].prev_hash = forged[1].hash.clone();
    forged[2].hash = forged[2].fields().hash();
    let forged = text(&forged);
    assert_eq!(verify_export(&forged, None).broken, None);
    let caught = verify_export_keyed(&forged, None, Some(&key()))
        .broken
        .unwrap();
    assert_eq!((caught.line, caught.kind), (2, BreakKind::MacMismatch));

    // A later line whose MAC was removed, after one verified with the key.
    let mut stripped = lines.clone();
    stripped[2].mac = None;
    stripped[2].key_id = None;
    stripped[2].format = ExportFormat::V1;
    let caught = verify_export_keyed(&text(&stripped), None, Some(&key()))
        .broken
        .unwrap();
    assert_eq!((caught.line, caught.kind), (3, BreakKind::MacMissing));

    // A version 1 line that carries a MAC is no line of either version.
    let mut mixed = lines;
    mixed[0].format = ExportFormat::V1;
    let caught = verify_export(&text(&mixed), None).broken.unwrap();
    assert_eq!((caught.line, caught.kind), (1, BreakKind::Unreadable));
}

#[test]
fn a_log_marked_and_keyed_from_the_start_has_no_events_before_the_key() {
    let store = Store::open_in_memory().unwrap();
    let marked: i64 = store
        .conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'unkeyed_last_id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(marked, 0);
    assert!(!store.has_keyed_events().unwrap());
    record(&store, "echo 1").unwrap();
    assert!(store.has_keyed_events().unwrap());
    let stored: Option<String> = store
        .conn
        .query_row("SELECT mac FROM events WHERE id = ?1", params![1], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(stored.map(|m| m.len()), Some(64));
}
