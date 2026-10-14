use openmoat_core::{Action, Decision, Verdict};
use rusqlite::{Connection, params};

use super::*;
use crate::store::chain::Fields;

fn fields() -> Fields<'static> {
    Fields {
        id: 1,
        ts_ms: 1_700_000_000_000,
        host: "claude-code",
        session_id: "s1",
        call_id: Some("c1"),
        cwd: None,
        tool: "Bash",
        action: r#"{"shell":{"command":"git status"}}"#,
        verdict: "allow",
        rules: r#"["dev-shell"]"#,
        reasons: r#"["ok"]"#,
        latency_us: 1200,
        prev_hash: GENESIS,
    }
}

#[test]
fn canonical_encoding_is_pinned() {
    // Changing this value breaks every chain already written: bump the domain tag
    // instead (chain.rs). The same value is computed independently from the
    // encoding as documented in `docs/ARCHITECTURE.md`.
    assert_eq!(
        fields().hash(),
        "a4c71c405a0719bae1d6cd1fa50a92b6bfdcdf41f6789c7eea604f63c549c774"
    );
    let encoded = fields().encode();
    assert!(encoded.starts_with(&[0, 0, 0, 0, 0, 0, 0, 19]));
    assert!(encoded.ends_with(GENESIS.as_bytes()));
}

#[test]
fn canonical_encoding_separates_fields() {
    let base = fields();
    let shifted = Fields {
        host: "claude-codes",
        session_id: "1",
        ..base
    };
    assert_ne!(base.hash(), shifted.hash());
    let absent = Fields {
        call_id: None,
        cwd: Some("c1"),
        ..base
    };
    assert_ne!(base.hash(), absent.hash());
    let empty = Fields {
        call_id: Some(""),
        ..base
    };
    assert_ne!(
        Fields {
            call_id: None,
            ..base
        }
        .hash(),
        empty.hash()
    );
}

fn record(store: &Store, command: &str) -> EventId {
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push("dev-shell".to_owned());
    decision.reasons.push("ok".to_owned());
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: Some("/p"),
            tool: "Bash",
            action: Some(&action),
            decision: &decision,
            latency_us: 900,
        })
        .unwrap()
}

fn chain_of(n: usize) -> Store {
    let store = Store::open_in_memory().unwrap();
    for i in 0..n {
        record(&store, &format!("echo {i}"));
    }
    store
}

fn broken(store: &Store) -> Option<ChainBreak> {
    store.verify_chain().unwrap().broken
}

#[test]
fn an_untouched_chain_verifies_and_links() {
    let store = chain_of(4);
    let report = store.verify_chain().unwrap();
    assert_eq!(report.events, 4);
    assert_eq!(report.unchained, 0);
    assert_eq!(report.broken, None);
    let events = store.session("s1").unwrap();
    assert_eq!(events[0].prev_hash.as_deref(), Some(GENESIS));
    for pair in events.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
    assert_eq!(report.head, events[3].hash);
    let empty = Store::open_in_memory().unwrap().verify_chain().unwrap();
    assert_eq!((empty.events, empty.head, empty.broken), (0, None, None));
}

#[test]
fn an_edited_field_is_detected_at_its_event() {
    for edit in [
        "UPDATE events SET verdict = 'deny' WHERE id = 2",
        "UPDATE events SET action = '{\"shell\":{\"command\":\"echo x\"}}' WHERE id = 2",
        "UPDATE events SET ts_ms = ts_ms + 1 WHERE id = 2",
        "UPDATE events SET cwd = NULL WHERE id = 2",
    ] {
        let store = chain_of(3);
        store.conn.execute(edit, []).unwrap();
        let expected = ChainBreak {
            id: EventId(2),
            kind: BreakKind::Edited,
        };
        assert_eq!(broken(&store), Some(expected), "{edit}");
    }
}

#[test]
fn a_cell_of_the_wrong_type_is_detected() {
    let store = chain_of(3);
    store
        .conn
        .execute("UPDATE events SET ts_ms = 'yesterday' WHERE id = 2", [])
        .unwrap();
    assert_eq!(broken(&store).unwrap().kind, BreakKind::Unreadable);
}

#[test]
fn a_deleted_middle_event_is_detected_at_the_next() {
    let store = chain_of(4);
    store
        .conn
        .execute("DELETE FROM events WHERE id = 2", [])
        .unwrap();
    let expected = ChainBreak {
        id: EventId(3),
        kind: BreakKind::Unlinked,
    };
    assert_eq!(broken(&store), Some(expected));
}

#[test]
fn reordered_events_are_detected() {
    let store = chain_of(4);
    store
        .conn
        .execute_batch(
            "UPDATE events SET id = 100 WHERE id = 2;
             UPDATE events SET id = 2 WHERE id = 3;
             UPDATE events SET id = 3 WHERE id = 100;",
        )
        .unwrap();
    assert_eq!(broken(&store).unwrap().id, EventId(2));
}

#[test]
fn a_removed_hash_does_not_pass_as_an_old_event() {
    let store = chain_of(3);
    store
        .conn
        .execute("UPDATE events SET hash = NULL, prev_hash = NULL", [])
        .unwrap();
    let expected = ChainBreak {
        id: EventId(1),
        kind: BreakKind::Unhashed,
    };
    assert_eq!(broken(&store), Some(expected));
}

#[test]
fn a_version_1_database_is_migrated_without_vouching_for_old_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    {
        let conn = Connection::open(&path).unwrap();
        schema::create_v1(&conn).unwrap();
        for id in 1..=2 {
            conn.execute(
                "INSERT INTO events (id, ts_ms, host, session_id, tool, action, verdict, rules, reasons, latency_us)
                 VALUES (?1, 0, 'codex', 'old', 'shell', 'null', 'allow', '[]', '[]', 5)",
                params![id],
            )
            .unwrap();
        }
    }
    // A read-only handle (`moat show` before any guard ran) reads it unchanged.
    let old = Store::open_read_only(&path).unwrap();
    assert_eq!(old.recent(5).unwrap()[0].hash, None);
    let report = old.verify_chain().unwrap();
    assert_eq!((report.events, report.unchained), (2, 2));
    drop(old);

    let store = Store::open(&path).unwrap();
    let id = record(&store, "git status");
    assert_eq!(id, EventId(3));
    let event = store.get(id).unwrap().unwrap();
    assert_eq!(event.prev_hash.as_deref(), Some(GENESIS));
    assert_eq!(store.session("old").unwrap()[1].hash, None);
    let report = store.verify_chain().unwrap();
    assert_eq!(report.events, 3);
    assert_eq!(report.unchained, 2);
    assert_eq!(report.broken, None);
    assert_eq!(report.head, event.hash);
    drop(store);
    // Reopening does not migrate twice.
    assert!(
        Store::open(&path)
            .unwrap()
            .verify_chain()
            .unwrap()
            .broken
            .is_none()
    );
}

#[test]
fn concurrent_writers_build_one_chain() {
    const THREADS: usize = 8;
    const EACH: usize = 25;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    drop(Store::open(&path).unwrap());
    let writers: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let store = Store::open_existing(&path).unwrap();
                for i in 0..EACH {
                    record(&store, &format!("echo {t}-{i}"));
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let report = Store::open_read_only(&path)
        .unwrap()
        .verify_chain()
        .unwrap();
    assert_eq!(report.events, (THREADS * EACH) as u64);
    assert_eq!(report.broken, None);
}

/// ADR-025: version 3 widens the verdict check for `defer`. A version-2 database
/// with a hashed chain keeps every row and hash, still verifies, and takes `defer`.
#[test]
fn a_version_2_database_is_migrated_with_its_chain_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        record(&store, "git status");
        record(&store, "git log");
        store.verify_chain().unwrap().head
    };
    // Put the table back as 0.5.0-rc.1 left it: the old check, `user_version` 2.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "ALTER TABLE events RENAME TO events_new;
             CREATE TABLE events (
                 id INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, host TEXT NOT NULL,
                 session_id TEXT NOT NULL, call_id TEXT, cwd TEXT, tool TEXT NOT NULL,
                 action TEXT NOT NULL,
                 verdict TEXT NOT NULL CHECK (verdict IN ('allow','ask','deny')),
                 rules TEXT NOT NULL, reasons TEXT NOT NULL, latency_us INTEGER NOT NULL,
                 prev_hash TEXT, hash TEXT);
             INSERT INTO events SELECT * FROM events_new;
             DROP TABLE events_new;
             PRAGMA user_version = 2;",
        )
        .unwrap();
        let refused = conn.execute(
            "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules, reasons, latency_us)
             VALUES (0, 'h', 's', 't', 'null', 'defer', '[]', '[]', 1)",
            [],
        );
        assert!(refused.is_err(), "the version-2 check refuses `defer`");
    }

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken, report.head), (2, None, head));
    let mut decision = Decision::new(Verdict::Defer);
    decision.rules.push("default".to_owned());
    decision.reasons.push("no rule matched".to_owned());
    let action = Action::Shell {
        command: "make deploy".to_owned(),
    };
    let id = store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: Some("/p"),
            tool: "Bash",
            action: Some(&action),
            decision: &decision,
            latency_us: 900,
        })
        .unwrap();
    assert_eq!(store.get(id).unwrap().unwrap().verdict, Verdict::Defer);
    assert!(store.verify_chain().unwrap().broken.is_none());
}

/// A database a newer build wrote is refused read-only too, not read with a
/// schema this build does not know.
#[test]
fn a_newer_schema_is_refused_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    drop(Store::open(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let refused = Store::open_read_only(&path).err().unwrap();
    assert!(
        matches!(refused, StoreError::SchemaTooNew { found: 99, .. }),
        "{refused}"
    );
}
