//! File provenance (ADR-029): the newest write row of a path decides, rows are
//! only appended, and a database from before version 4 still opens.

use rusqlite::Connection;

use super::*;

fn row(kind: ProvenanceKind, path: &str, sha: Option<&str>, source: &str) -> NewProvenance {
    NewProvenance {
        kind,
        path: path.to_owned(),
        sha256: sha.map(str::to_owned),
        source: source.to_owned(),
    }
}

fn event(store: &Store, session: &str) -> EventId {
    let d = decision(Verdict::Allow, "dev-files", "ok");
    let action = Action::FsWrite {
        path: "/p/run.sh".into(),
    };
    let mut e = sample(&d, &action);
    e.session_id = session;
    store.record(&e).unwrap()
}

#[test]
fn the_newest_write_row_of_a_path_is_its_provenance() {
    let store = Store::open_in_memory().unwrap();
    assert!(!store.has_provenance().unwrap());
    assert_eq!(store.file_provenance("/p/run.sh").unwrap(), None);

    let a = event(&store, "a");
    let tainted = row(
        ProvenanceKind::TaintedWrite,
        "/p/run.sh",
        Some("ab"),
        "fetch x.example",
    );
    store
        .add_provenance(a, "claude-code", "a", &[tainted])
        .unwrap();
    assert!(store.has_provenance().unwrap());
    let found = store.file_provenance("/p/run.sh").unwrap().unwrap();
    assert_eq!(
        (found.event_id, found.session_id.as_str(), found.tainted),
        (a, "a", true)
    );
    assert_eq!(found.sha256.as_deref(), Some("ab"));
    assert_eq!(found.source, "fetch x.example");
    assert_eq!(store.file_provenance("/p/other.sh").unwrap(), None);

    // a read row of the path does not count as a write
    let b = event(&store, "b");
    let read = row(
        ProvenanceKind::TaintedRead,
        "/p/run.sh",
        None,
        "read /p/run.sh",
    );
    store
        .add_provenance(b, "claude-code", "b", &[read])
        .unwrap();
    assert_eq!(
        store
            .file_provenance("/p/run.sh")
            .unwrap()
            .unwrap()
            .event_id,
        a
    );

    let c = event(&store, "c");
    let clean = row(ProvenanceKind::CleanWrite, "/p/run.sh", Some("cd"), "");
    store
        .add_provenance(c, "claude-code", "c", &[clean])
        .unwrap();
    let found = store.file_provenance("/p/run.sh").unwrap().unwrap();
    assert_eq!((found.event_id, found.tainted), (c, false));
}

#[test]
fn a_session_exposure_names_its_first_read_and_its_latest_event() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.exposure("b", "claude-code").unwrap(), None);
    let first = event(&store, "b");
    let one = row(
        ProvenanceKind::TaintedRead,
        "/p/run.sh",
        None,
        "read /p/run.sh",
    );
    store
        .add_provenance(first, "claude-code", "b", &[one])
        .unwrap();
    let later = event(&store, "b");
    let two = row(ProvenanceKind::TaintedRead, "/p/x.py", None, "read /p/x.py");
    store
        .add_provenance(later, "claude-code", "b", &[two])
        .unwrap();
    let exposure = store.exposure("b", "claude-code").unwrap().unwrap();
    assert_eq!(exposure.source, "read /p/run.sh");
    assert_eq!(exposure.last_event, later);
    assert_eq!(store.exposure("b", "codex").unwrap(), None);
    assert_eq!(store.exposure("a", "claude-code").unwrap(), None);
    // a session's own tainted writes are no exposure
    let w = row(
        ProvenanceKind::TaintedWrite,
        "/p/y.sh",
        None,
        "fetch x.example",
    );
    store
        .add_provenance(later, "claude-code", "w", &[w])
        .unwrap();
    assert_eq!(store.exposure("w", "claude-code").unwrap(), None);
}

#[test]
fn provenance_rows_cannot_be_changed_or_deleted() {
    let store = Store::open_in_memory().unwrap();
    let a = event(&store, "a");
    let tainted = row(
        ProvenanceKind::TaintedWrite,
        "/p/run.sh",
        None,
        "fetch x.example",
    );
    store
        .add_provenance(a, "claude-code", "a", &[tainted])
        .unwrap();
    for statement in [
        "UPDATE provenance SET kind = 'clean-write'",
        "DELETE FROM provenance",
    ] {
        assert!(store.conn.execute(statement, []).is_err(), "{statement}");
    }
    assert!(store.file_provenance("/p/run.sh").unwrap().unwrap().tainted);
}

#[test]
fn known_secret_values_are_masked_in_provenance_rows() {
    let token = format!("{}{}", "s3cr3t-", "x".repeat(24));
    let store = Store::open_in_memory()
        .unwrap()
        .with_secrets(KnownSecrets::new([token.as_str()]).unwrap());
    let a = event(&store, "a");
    let path = format!("/p/{token}.sh");
    let tainted = row(
        ProvenanceKind::TaintedWrite,
        &path,
        None,
        &format!("fetch {token}"),
    );
    store
        .add_provenance(a, "claude-code", "a", &[tainted])
        .unwrap();
    let stored: String = store
        .conn
        .query_row("SELECT path || source FROM provenance", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.contains(&token), "{stored}");
    // looked up through the same mask, the row is still found
    assert!(store.file_provenance(&path).unwrap().is_some());
}

/// A version-3 database (0.5.x) has no provenance table: a read-only handle
/// reads it as having no rows, and the first writable open adds the table
/// without touching the events or their chain.
#[test]
fn a_version_3_database_is_migrated_to_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        event(&store, "a");
        store.verify_chain().unwrap().head
    };
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TRIGGER provenance_no_update; DROP TRIGGER provenance_no_delete;
             DROP TABLE provenance; PRAGMA user_version = 3;",
        )
        .unwrap();

    let old = Store::open_read_only(&path).unwrap();
    assert!(!old.has_provenance().unwrap());
    assert_eq!(old.file_provenance("/p/run.sh").unwrap(), None);
    assert_eq!(old.exposure("a", "claude-code").unwrap(), None);
    drop(old);

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken, report.head), (1, None, head));
    let b = event(&store, "b");
    let tainted = row(
        ProvenanceKind::TaintedWrite,
        "/p/run.sh",
        None,
        "fetch x.example",
    );
    store
        .add_provenance(b, "claude-code", "b", &[tainted])
        .unwrap();
    assert!(store.file_provenance("/p/run.sh").unwrap().unwrap().tainted);
    drop(store);
    assert!(
        Store::open_read_only(&path)
            .unwrap()
            .has_provenance()
            .unwrap()
    );
}
