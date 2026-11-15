//! Rewrites that get around a keyed chain by what the key does not cover:
//! another key's id on a forged export tail, a log cut back to the key's start
//! and rewritten before it, a log cut below the start, an insert that leaves
//! its id to `SQLite` (ADR-101).

use openmoat_core::{Decision, Verdict};
use rusqlite::Connection;

use super::*;
use crate::testing::{rewrite_without_key, truncate_after};

fn record(store: &Store, command: &str) -> Result<EventId, StoreError> {
    let decision = Decision::new(Verdict::Allow);
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store.record(&NewEvent {
        host: "claude-code",
        session_id: "s",
        call_id: None,
        cwd: None,
        tool: "Bash",
        action: Some(&action),
        decision: &decision,
        latency_us: 1,
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

fn text(lines: &[ExportedEvent]) -> String {
    lines
        .iter()
        .map(|l| serde_json::to_string(l).unwrap() + "\n")
        .collect()
}

fn broken(report: &ExportReport) -> Option<(usize, BreakKind)> {
    report.broken.as_ref().map(|b| (b.line, b.kind))
}

/// The key a log of `n` events written after `upto` of them would have had,
/// made when it reached `upto`.
fn key_made_at(path: &std::path::Path, upto: i64) -> ChainKey {
    let hash = Store::open_read_only(path)
        .unwrap()
        .hash_of(EventId(upto))
        .unwrap();
    ChainKey::new(&[9; 32], EventId(upto), hash.as_deref())
}

#[test]
fn a_forged_export_tail_naming_another_key_fails_after_lines_this_key_verified() {
    let (_dir, path) = keyed_log(4);
    rewrite_without_key(&path, 3, "deny").unwrap();
    let mut lines = Store::open_read_only(&path)
        .unwrap()
        .with_chain_key(key())
        .export(&ExportFilter::default())
        .unwrap();
    let own = verify_export_keyed(&text(&lines), None, Some(&key()));
    assert_eq!(broken(&own), Some((3, BreakKind::MacMismatch)));
    for line in lines.iter_mut().skip(2) {
        line.key_id = Some("ffffffffffffffff".to_owned());
    }
    let forged = text(&lines);
    let report = verify_export_keyed(&forged, None, Some(&key()));
    assert_eq!(broken(&report), Some((3, BreakKind::KeyMismatch)));
    // Without the key, two key ids in one file fail too.
    assert_eq!(
        broken(&verify_export(&forged, None)),
        Some((3, BreakKind::KeyMismatch))
    );
}

#[test]
fn a_mac_without_a_key_id_is_checked_with_the_key_and_another_logs_export_is_not() {
    let (_dir, path) = keyed_log(3);
    // Exported by a handle without the key: MACs, no key id.
    let lines = Store::open_read_only(&path)
        .unwrap()
        .export(&ExportFilter::default())
        .unwrap();
    assert!(lines.iter().all(|l| l.key_id.is_none() && l.mac.is_some()));
    let report = verify_export_keyed(&text(&lines), None, Some(&key()));
    assert_eq!((report.broken, report.keyed), (None, 3));
    let mut forged = lines.clone();
    forged[0].mac = Some("0".repeat(64));
    let report = verify_export_keyed(&text(&forged), None, Some(&key()));
    assert_eq!(broken(&report), Some((1, BreakKind::MacMismatch)));
    // A file that names only another key is another log's: nothing verified
    // with this one, and the report says so.
    let mut other = lines;
    for line in &mut other {
        line.key_id = Some("ffffffffffffffff".to_owned());
    }
    let report = verify_export_keyed(&text(&other), None, Some(&key()));
    assert_eq!(
        (report.broken, report.keyed, report.keyed_unchecked),
        (None, 0, 3)
    );
    assert!(report.key_given);
}

#[test]
fn an_export_stripped_to_version_1_fails_where_the_key_says_events_are_keyed() {
    let (_dir, path) = keyed_log(4);
    rewrite_without_key(&path, 2, "deny").unwrap();
    let mut lines = Store::open_read_only(&path)
        .unwrap()
        .export(&ExportFilter::default())
        .unwrap();
    for line in &mut lines {
        line.mac = None;
        line.key_id = None;
        line.format = ExportFormat::V1;
    }
    let stripped = text(&lines);
    assert_eq!(verify_export(&stripped, None).broken, None);
    let report = verify_export_keyed(&stripped, None, Some(&key()));
    assert_eq!(broken(&report), Some((1, BreakKind::MacMissing)));
    // Lines up to the key's start are from before it and need none.
    let later = key_made_at(&path, 4);
    assert_eq!(
        verify_export_keyed(&stripped, None, Some(&later)).broken,
        None
    );
}

#[test]
fn a_log_cut_below_the_keys_start_does_not_verify() {
    let (_dir, path) = keyed_log(4);
    let made_at_three = key_made_at(&path, 3);
    truncate_after(&path, 1).unwrap();
    let report = Store::open_read_only(&path)
        .unwrap()
        .with_chain_key(made_at_three)
        .verify_chain()
        .unwrap();
    let expected = ChainBreak {
        id: EventId(3),
        kind: BreakKind::Truncated,
    };
    assert_eq!(report.broken, Some(expected));
}

#[test]
fn events_before_the_key_rewritten_after_its_keyed_events_were_dropped_are_detected() {
    let (_dir, path) = keyed_log(4);
    let key = key_made_at(&path, 2);
    // Drop every keyed event, then rewrite those before the key.
    truncate_after(&path, 2).unwrap();
    rewrite_without_key(&path, 1, "deny").unwrap();
    let report = Store::open_read_only(&path)
        .unwrap()
        .with_chain_key(made_at_two_of(&key))
        .verify_chain()
        .unwrap();
    let expected = ChainBreak {
        id: EventId(2),
        kind: BreakKind::KeyStartChanged,
    };
    assert_eq!(report.broken, Some(expected));
    // Nor does a writer launder it with a keyed event on top.
    let store = Store::open_existing(&path).unwrap().with_chain_key(key);
    let refused = record(&store, "laundered").err().unwrap();
    assert!(
        matches!(refused, StoreError::KeyStartChanged { after: EventId(2) }),
        "{refused}"
    );
    assert_eq!(store.count().unwrap(), 2);
}

/// The same key again (a key is not `Clone`, as it is never copied by value).
fn made_at_two_of(key: &ChainKey) -> ChainKey {
    ChainKey::parse(&key.encode()).unwrap()
}

#[test]
fn an_insert_that_leaves_its_id_to_sqlite_needs_a_mac_too() {
    let (_dir, path) = keyed_log(1);
    let refused = Connection::open(&path).unwrap().execute(
        "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules, reasons,
                             latency_us, prev_hash, hash)
         VALUES (0, 'h', 's', 't', 'null', 'allow', '[]', '[]', 1, 'x', 'y')",
        [],
    );
    let error = refused.err().unwrap().to_string();
    assert!(error.contains("audit key"), "{error}");
}

#[test]
fn a_version_set_back_by_hand_is_no_upgrade_a_key_may_be_made_in() {
    let (_dir, path) = keyed_log(1);
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 11)
        .unwrap();
    assert!(!Store::open_existing(&path).unwrap().upgraded_to_keyed());
    let fresh = tempfile::tempdir().unwrap();
    assert!(
        Store::open(&fresh.path().join("audit.db"))
            .unwrap()
            .upgraded_to_keyed(),
        "a new log is made at version 12 by this open"
    );
}
