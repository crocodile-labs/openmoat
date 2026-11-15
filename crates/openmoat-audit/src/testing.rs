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
