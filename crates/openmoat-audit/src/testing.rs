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
