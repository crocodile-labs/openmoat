//! The files each session wrote (ADR-039): one row per file and session, the
//! newest write wins, the table stays bounded, and a version-4 database opens.

use rusqlite::Connection;

use super::*;
use crate::store::session_writes::{MAX_AGE_MS, MAX_ROWS, PRUNE_EVERY};

fn write(path: &str, sha: Option<&str>) -> SessionWrite {
    SessionWrite {
        path: path.to_owned(),
        sha256: sha.map(str::to_owned),
        before: None,
    }
}

fn event(store: &Store, session: &str) -> EventId {
    let d = decision(Verdict::Allow, "project-fs", "ok");
    let action = Action::FsWrite {
        path: "/p/x.py".into(),
    };
    let mut e = sample(&d, &action);
    e.session_id = session;
    store.record(&e).unwrap()
}

fn wrote(store: &Store, host: &str, session: &str, path: &str) -> Option<Written> {
    store
        .session_wrote(host, session, &[path.to_owned()])
        .unwrap()
        .pop()
}

#[test]
fn a_session_finds_only_the_files_it_wrote() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(wrote(&store, "gemini-cli", "a", "/p/x.py"), None);
    let first = event(&store, "a");
    store
        .add_session_writes(first, "gemini-cli", "a", &[write("/p/x.py", Some("ab"))])
        .unwrap();
    let found = wrote(&store, "gemini-cli", "a", "/p/x.py").unwrap();
    assert_eq!(
        (found.event_id, found.sha256.as_deref()),
        (first, Some("ab"))
    );
    // another session, another host or another file: not written by it
    assert_eq!(wrote(&store, "gemini-cli", "b", "/p/x.py"), None);
    assert_eq!(wrote(&store, "opencode", "a", "/p/x.py"), None);
    assert_eq!(wrote(&store, "gemini-cli", "a", "/p/y.py"), None);

    // writing it again names the newer call; a shell write has no hash
    let again = event(&store, "a");
    store
        .add_session_writes(again, "gemini-cli", "a", &[write("/p/x.py", None)])
        .unwrap();
    let found = wrote(&store, "gemini-cli", "a", "/p/x.py").unwrap();
    assert_eq!((found.event_id, found.sha256), (again, None));
    let rows: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM session_writes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn old_rows_and_rows_past_the_limit_are_removed() {
    // the next row's id is a multiple of `PRUNE_EVERY`, so adding it prunes
    let limit = PRUNE_EVERY * 5000 - 1;
    let far = (limit + MAX_ROWS + PRUNE_EVERY) / PRUNE_EVERY * PRUNE_EVERY - 1;
    let store = Store::open_in_memory().unwrap();
    let e = event(&store, "a");
    store
        .conn
        .execute(
            "INSERT INTO session_writes (event_id, ts_ms, host, session_id, path)
             VALUES (?1, ?2, 'pi', 'old', '/p/old.sh')",
            params![e.0, now_ms() - MAX_AGE_MS - 1],
        )
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO session_writes (id, event_id, ts_ms, host, session_id, path)
             VALUES (?1, ?2, ?3, 'pi', 'limit', '/p/first.sh')",
            params![limit, e.0, now_ms()],
        )
        .unwrap();
    store
        .add_session_writes(e, "pi", "a", &[write("/p/new.sh", None)])
        .unwrap();
    assert_eq!(wrote(&store, "pi", "old", "/p/old.sh"), None);
    assert!(wrote(&store, "pi", "a", "/p/new.sh").is_some());
    // the new row is the next id after `limit`, which is still within the limit
    assert!(wrote(&store, "pi", "limit", "/p/first.sh").is_some());
    store
        .conn
        .execute(
            "INSERT INTO session_writes (id, event_id, ts_ms, host, session_id, path)
             VALUES (?1, ?2, ?3, 'pi', 'far', '/p/far.sh')",
            params![far, e.0, now_ms()],
        )
        .unwrap();
    store
        .add_session_writes(e, "pi", "a", &[write("/p/newer.sh", None)])
        .unwrap();
    assert_eq!(wrote(&store, "pi", "limit", "/p/first.sh"), None);
    assert!(wrote(&store, "pi", "far", "/p/far.sh").is_some());
}

#[test]
fn known_secret_values_are_masked_in_session_writes() {
    let token = format!("{}{}", "s3cr3t-", "x".repeat(24));
    let store = Store::open_in_memory()
        .unwrap()
        .with_secrets(KnownSecrets::new([token.as_str()]).unwrap());
    let e = event(&store, "a");
    let path = format!("/p/{token}.sh");
    store
        .add_session_writes(e, "pi", "a", &[write(&path, None)])
        .unwrap();
    let stored: String = store
        .conn
        .query_row("SELECT path FROM session_writes", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.contains(&token), "{stored}");
    assert!(wrote(&store, "pi", "a", &path).is_some());
}

/// A version-4 database (0.10.x) has no session writes: a read-only handle
/// reads it as empty, and the first writable open adds the table without
/// touching the events or their chain.
#[test]
fn a_version_4_database_is_migrated_to_session_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        event(&store, "a");
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE session_writes; PRAGMA user_version = 4;")
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    assert_eq!(wrote(&old, "pi", "a", "/p/x.py"), None);
    old.add_session_writes(EventId(1), "pi", "a", &[write("/p/x.py", None)])
        .unwrap();
    drop(old);

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken, report.head), (1, None, head));
    let e = event(&store, "a");
    store
        .add_session_writes(e, "pi", "a", &[write("/p/x.py", None)])
        .unwrap();
    assert!(wrote(&store, "pi", "a", "/p/x.py").is_some());
}

/// The state of the file before a write is kept with the write (ADR-048): a
/// hash, `""` for no file, or nothing when it was not known.
#[test]
fn the_state_of_the_file_before_a_write_is_kept() {
    let store = Store::open_in_memory().unwrap();
    let e = event(&store, "a");
    let mut created = write("/p/x.py", Some("new"));
    created.before = Some(String::new());
    let mut changed = write("/p/y.py", Some("new"));
    changed.before = Some("old".to_owned());
    store
        .add_session_writes(e, "pi", "a", &[created, changed, write("/p/z.py", None)])
        .unwrap();
    let before = |path| wrote(&store, "pi", "a", path).unwrap().before;
    assert_eq!(before("/p/x.py"), Some(String::new()));
    assert_eq!(before("/p/y.py"), Some("old".to_owned()));
    assert_eq!(before("/p/z.py"), None);
}

/// A version-6 database (0.11.0) keeps no state before a write: a read-only
/// handle reads its rows with none, and the first writable open adds the
/// column while keeping the rows and the chain.
#[test]
fn a_version_6_database_is_migrated_to_keep_the_state_before_a_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        let e = event(&store, "a");
        store
            .add_session_writes(e, "pi", "a", &[write("/p/x.py", Some("ab"))])
            .unwrap();
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "ALTER TABLE session_writes DROP COLUMN before_sha256; PRAGMA user_version = 6;",
        )
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    let found = wrote(&old, "pi", "a", "/p/x.py").unwrap();
    assert_eq!((found.sha256.as_deref(), found.before), (Some("ab"), None));
    drop(old);

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken, report.head), (1, None, head));
    assert_eq!(wrote(&store, "pi", "a", "/p/x.py").unwrap().before, None);
    let e = event(&store, "a");
    let mut again = write("/p/x.py", Some("ef"));
    again.before = Some("ab".to_owned());
    store.add_session_writes(e, "pi", "a", &[again]).unwrap();
    assert_eq!(
        wrote(&store, "pi", "a", "/p/x.py").unwrap().before,
        Some("ab".to_owned())
    );
}

#[test]
fn a_session_that_wrote_nothing_is_told_from_one_that_did() {
    let store = Store::open_in_memory().unwrap();
    assert!(!store.session_wrote_any("pi", "a").unwrap());
    let e = event(&store, "a");
    store
        .add_session_writes(e, "pi", "a", &[write("/p/x.sh", None)])
        .unwrap();
    assert!(store.session_wrote_any("pi", "a").unwrap());
    assert!(!store.session_wrote_any("pi", "b").unwrap());
    assert!(!store.session_wrote_any("codex", "a").unwrap());
}
