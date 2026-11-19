//! A log as each older release left it, with many events across sessions, opened by
//! this build: read first (as the guard's taint fold reads it), then upgraded by the
//! first writer, keyed from there on, and the chain verifies across the step.

use rusqlite::Connection;

use super::*;
use crate::testing::{VERSIONS_BEFORE_THE_KEY, as_written_by};

/// Sessions in the log, and the calls each holds before the copies.
const SESSIONS: [&str; 3] = ["long", "s2", "s3"];
const CALLS: usize = 4;
/// How often the recorded events are repeated in the older log.
const REPEAT: usize = 30;

/// The verdicts a session's calls get, in turn: every kind a build stores.
const VERDICTS: [Verdict; 4] = [
    Verdict::Allow,
    Verdict::Review,
    Verdict::Defer,
    Verdict::Deny,
];

fn record(store: &Store, session: &str, i: usize) {
    let verdict = VERDICTS[i % VERDICTS.len()];
    let d = decision(verdict, "dev-shell", "ok");
    let action = Action::Shell {
        command: format!("cargo test -p crate{i}"),
    };
    let mut event = sample(&d, &action);
    event.session_id = session;
    store.record(&event).unwrap();
}

/// A log of this build with [`CALLS`] calls in each session, rebuilt as
/// `version` wrote it with every event [`REPEAT`] times: the events an
/// upgrade finds.
fn older_log(version: i64) -> (tempfile::TempDir, std::path::PathBuf, u64) {
    static CURRENT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let current = CURRENT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = Store::open(&path).unwrap().with_chain_key(key());
        for i in 0..CALLS {
            for session in SESSIONS {
                record(&store, session, i);
            }
        }
        drop(store);
        std::fs::read(&path).unwrap()
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    std::fs::write(&path, current).unwrap();
    as_written_by(&path, version, REPEAT).unwrap();
    let events = u64::try_from(SESSIONS.len() * CALLS * REPEAT).unwrap();
    (dir, path, events)
}

fn user_version(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn a_log_of_every_older_version_is_read_upgraded_and_keyed_after_its_events() {
    for version in VERSIONS_BEFORE_THE_KEY {
        let (_dir, path, old) = older_log(version);
        assert_eq!(user_version(&path), version);

        // Read-only first, as the guard's taint fold reads a long session before
        // anything is recorded: every event of the session, verdicts as they mean.
        let reader = Store::open_read_only(&path).unwrap();
        let long = reader.session_after("long", EventId(0)).unwrap();
        assert_eq!(long.len(), CALLS * REPEAT, "version {version}");
        let held = long.iter().filter(|e| e.verdict == Verdict::Review).count();
        assert!(held > 0, "version {version}: a held call reads as `review`");
        let report = reader.verify_chain().unwrap();
        assert_eq!(report.broken, None, "version {version}");
        assert_eq!(report.events, old, "version {version}");
        drop(reader);

        // The first writer upgrades it, and only that open says so: the one
        // that must make the key.
        let store = Store::open_existing(&path).unwrap();
        assert!(store.upgraded_to_keyed(), "version {version}");
        assert!(!store.has_keyed_events().unwrap(), "version {version}");
        assert!(!Store::open_existing(&path).unwrap().upgraded_to_keyed());
        assert_eq!(user_version(&path), schema::SCHEMA_VERSION);
        let (after, after_hash) = store.key_start().unwrap();
        assert_eq!(after, EventId(i64::try_from(old).unwrap()));
        let store = upgraded(store);
        for i in 0..2 {
            record(&store, "long", i);
        }
        drop(store);

        let made = || ChainKey::new(&[9; 32], after, after_hash.as_deref());
        let reader = Store::open_read_only(&path).unwrap().with_chain_key(made());
        // `openmoat audit export` and `audit verify` of the whole log.
        let text: String = reader
            .export(&ExportFilter::default())
            .unwrap()
            .iter()
            .map(|l| serde_json::to_string(l).unwrap() + "\n")
            .collect();
        let exported = verify_export_keyed(&text, None, Some(&made()));
        assert_eq!(exported.broken, None, "version {version}");
        // Events from before the chain carry no hash to verify an export by.
        let unchained = if version < schema::CHAIN_VERSION {
            old
        } else {
            0
        };
        assert_eq!(exported.events, old + 2 - unchained, "version {version}");
        let report = reader.verify_chain().unwrap();
        assert_eq!(report.broken, None, "version {version}");
        assert_eq!(
            (report.events, report.keyed),
            (old + 2, 2),
            "version {version}"
        );
        assert_eq!(report.keyed_after, Some(after), "version {version}");
        assert_eq!(report.unchained, unchained, "version {version}");
    }
}

/// An open of an older log that has no key to record with still upgrades it:
/// what every writer that skips the key's module did (#837). The upgrade is
/// then done and no later open reports it, so only the first writer may make
/// the key, which is why every writable open goes through that module.
#[test]
fn an_upgrade_is_reported_once_whichever_open_does_it() {
    let (_dir, path, _) = older_log(11);
    let unkeyed = Store::open_existing(&path).unwrap();
    assert!(unkeyed.upgraded_to_keyed());
    drop(unkeyed);
    let next = Store::open_existing(&path).unwrap();
    assert!(!next.upgraded_to_keyed());
    assert!(matches!(
        next.record(&sample(
            &decision(Verdict::Allow, "dev-shell", "ok"),
            &Action::Shell {
                command: "true".into()
            }
        )),
        Err(StoreError::KeyMissing)
    ));
}
