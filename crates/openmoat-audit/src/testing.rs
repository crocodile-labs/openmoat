//! Test support for other crates: tamper with a stored event the way an attacker
//! with write access to the database would, so a test can check that the hash
//! chain notices. Compiled only with the `test-support` feature.

use std::path::Path;

use crate::StoreError;

/// Overwrite the verdict and rules of event `id` in the database at `path`
/// without touching its hash, as a direct edit of `audit.db` would.
///
/// # Errors
///
/// Returns [`StoreError`] if the database cannot be opened or written.
pub fn tamper_with_event(
    path: &Path,
    id: i64,
    verdict: &str,
    rules_json: &str,
) -> Result<(), StoreError> {
    let conn = rusqlite::Connection::open(path).map_err(StoreError::from)?;
    conn.execute(
        "UPDATE events SET verdict = ?1, rules = ?2 WHERE id = ?3",
        rusqlite::params![verdict, rules_json, id],
    )
    .map_err(StoreError::from)?;
    Ok(())
}

/// Delete every event after `id`, as someone who wants the newest decisions
/// gone would: what is left is a valid, shorter chain.
///
/// # Errors
///
/// Returns [`StoreError`] if the database cannot be opened or written.
pub fn truncate_after(path: &Path, id: i64) -> Result<(), StoreError> {
    let conn = rusqlite::Connection::open(path).map_err(StoreError::from)?;
    conn.execute("DELETE FROM events WHERE id > ?1", rusqlite::params![id])
        .map_err(StoreError::from)?;
    Ok(())
}

/// Make the log at `path` look as one written before the audit key existed
/// (ADR-101): no event has a MAC, and version 12's mark is after the newest.
///
/// # Errors
///
/// Returns [`StoreError`] if the database cannot be opened or written.
pub fn as_before_the_key(path: &Path) -> Result<(), StoreError> {
    let conn = rusqlite::Connection::open(path).map_err(StoreError::from)?;
    conn.execute_batch(
        "UPDATE events SET mac = NULL;
         UPDATE meta SET value = COALESCE((SELECT MAX(id) FROM events), 0)
             WHERE key = 'unkeyed_last_id';",
    )
    .map_err(StoreError::from)?;
    Ok(())
}

/// Put the log at `path` back as schema version 11 left it: no MAC column, no
/// mark of where keyed events start, no trigger. The next writable open
/// upgrades it as it would a log an older build wrote.
///
/// # Errors
///
/// Returns [`StoreError`] if the database cannot be opened or written.
pub fn as_before_version_12(path: &Path) -> Result<(), StoreError> {
    let conn = rusqlite::Connection::open(path).map_err(StoreError::from)?;
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS events_keyed;
         ALTER TABLE events DROP COLUMN mac;
         DELETE FROM meta WHERE key = 'unkeyed_last_id';
         PRAGMA user_version = 11;",
    )
    .map_err(StoreError::from)?;
    Ok(())
}

/// The schema versions a log may have been left at by a release before the
/// audit key (version 12, 0.22.0). Each one's layout differs from the next by
/// one ladder step, so the upgrade tests run once per version. A later schema
/// version needs its own way to write keyed events as its predecessor did.
pub const VERSIONS_BEFORE_THE_KEY: std::ops::RangeInclusive<i64> = 1..=11;

/// Rebuild the log at `path` as the build of schema `version` (one of
/// [`VERSIONS_BEFORE_THE_KEY`]) would have written it, holding the events the
/// log holds now `repeat` times over, in order, numbered on from 1: the state
/// an upgrade finds. The tables are laid out by the same migration steps that
/// build ran; events carry no MAC, are hashed into the chain from version 2
/// (before that they had no hash), and a `review` is stored as `ask` before
/// version 8 and a `defer` as `ask` before version 3, as those builds wrote
/// them. Nothing else is kept: no lookup table, no fold cache, no MAC.
///
/// No handle on `path` may be open: the file is replaced.
///
/// # Panics
///
/// When `version` is not one of [`VERSIONS_BEFORE_THE_KEY`].
///
/// # Errors
///
/// Returns [`StoreError`] if a database cannot be opened, read or written.
pub fn as_written_by(path: &Path, version: i64, repeat: usize) -> Result<(), StoreError> {
    assert!(
        VERSIONS_BEFORE_THE_KEY.contains(&version),
        "no older schema version {version}"
    );
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".v{version}"));
    let older = std::path::PathBuf::from(name);
    remove_database(&older)?;
    {
        let conn = rusqlite::Connection::open(&older)?;
        crate::store::create_at(&conn, version)?;
        conn.execute("ATTACH DATABASE ?1 AS now", [path.to_string_lossy()])?;
        let copy = "INSERT INTO main.events (ts_ms, host, session_id, call_id, cwd, tool, action,
                                             verdict, rules, reasons, latency_us)
             SELECT ts_ms, host, session_id, call_id, cwd, tool, action,
                    CASE WHEN verdict = 'review' AND ?1 < 8 THEN 'ask'
                         WHEN verdict = 'defer' AND ?1 < 3 THEN 'ask'
                         ELSE verdict END,
                    rules, reasons, latency_us
             FROM now.events ORDER BY id";
        // One transaction: a write per row would wait for the disk each time.
        conn.execute_batch("BEGIN")?;
        for _ in 0..repeat {
            conn.execute(copy, [version])?;
        }
        if version >= 2 {
            crate::store::rehash_from(&conn, 1)?;
        }
        conn.execute_batch("COMMIT; DETACH DATABASE now")?;
    }
    // The file keeps the access the log had (owner-only, as every build made it).
    let access = std::fs::metadata(path)
        .map_err(StoreError::Io)?
        .permissions();
    std::fs::set_permissions(&older, access).map_err(StoreError::Io)?;
    remove_database(path)?;
    std::fs::rename(&older, path).map_err(StoreError::Io)?;
    Ok(())
}

/// Remove the database at `path` with its write-ahead log and shared memory
/// files, when there.
fn remove_database(path: &Path) -> Result<(), StoreError> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::remove_file(std::path::PathBuf::from(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(StoreError::Io(e)),
            _ => {}
        }
    }
    Ok(())
}

/// Rewrite the verdict of event `id` and recompute its hash and the hashes
/// of every event after it, as someone who can write `audit.db` but not read
/// the audit key would: the hash chain verifies again, the MACs do not.
///
/// # Errors
///
/// Returns [`StoreError`] if the database cannot be opened or written.
pub fn rewrite_without_key(path: &Path, id: i64, verdict: &str) -> Result<(), StoreError> {
    let conn = rusqlite::Connection::open(path).map_err(StoreError::from)?;
    conn.execute(
        "UPDATE events SET verdict = ?1 WHERE id = ?2",
        rusqlite::params![verdict, id],
    )?;
    crate::store::rehash_from(&conn, id)
}
