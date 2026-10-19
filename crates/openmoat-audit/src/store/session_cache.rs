//! What a session's earlier calls folded to, so that a guard call late in a
//! long session reads only the events recorded since (#570).
//!
//! The cache is a convenience beside the events, never a source of truth: it
//! is outside the hash chain, a caller looks a row up by the `digest` of what
//! the fold depends on and folds from the first event when there is none, and
//! a cache that cannot be read is treated as absent. A session keeps one row
//! per digest (up to `ROWS_PER_SESSION`), so calls of one session that fold
//! under different digests, such as calls from two working directories, each
//! read on from their own row instead of replacing each other's. The table is
//! created on first write, so the schema version (and older builds' view of
//! the database) is unchanged; the `session_cache` table older builds wrote,
//! one row per session, is left to them.

use std::time::Duration;

use rusqlite::{ErrorCode, OptionalExtension as _, params};

use super::{EventId, Store, StoreError, row_to_event};
use crate::store::Event;

const TABLE: &str = "CREATE TABLE IF NOT EXISTS session_folds (
    session_id  TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    digest      TEXT    NOT NULL,
    upto        INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    touched     INTEGER NOT NULL,
    PRIMARY KEY (session_id, host, digest)
)";

/// The rows one session keeps on one host; the least recently written goes
/// first. Each digest is a working directory or a policy the session's calls
/// were decided under, so a handful covers a session.
const ROWS_PER_SESSION: i64 = 16;

/// A session's folded state as of event `upto`, computed under `digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    /// What the fold depended on (the caller's own spelling); a state under
    /// another digest does not apply.
    pub digest: String,
    /// The newest event of the session the state includes.
    pub upto: EventId,
    /// The folded state, in the caller's own format.
    pub state: String,
}

impl Store {
    /// The events of one session recorded after `after`, oldest first.
    pub fn session_after(
        &self,
        session_id: &str,
        after: EventId,
    ) -> Result<Vec<Event>, StoreError> {
        self.session_page(session_id, after, usize::MAX)
    }

    /// At most `limit` events of one session recorded after `after`, oldest
    /// first.
    pub fn session_page(
        &self,
        session_id: &str,
        after: EventId,
        limit: usize,
    ) -> Result<Vec<Event>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE session_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
            self.select()
        ))?;
        let session_id = self.secrets.redact(session_id);
        let rows = stmt.query_map(params![session_id, after.0, limit], row_to_event)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Whether `session_id` has an event of `host` with call id `call_id`.
    /// The ids are redacted as [`Store::record`] redacts them.
    pub fn session_has(
        &self,
        session_id: &str,
        host: &str,
        call_id: &str,
    ) -> Result<bool, StoreError> {
        let session_id = self.secrets.redact(session_id);
        let host = self.secrets.redact(host);
        let call_id = self.secrets.redact(call_id);
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM events WHERE session_id = ?1 AND host = ?2 AND call_id = ?3 LIMIT 1",
                params![session_id, host, call_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The cached state of `session_id` on `host` under `digest`, if one was
    /// written.
    pub fn session_cache(
        &self,
        session_id: &str,
        host: &str,
        digest: &str,
    ) -> Result<Option<Cached>, StoreError> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_folds'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Ok(None);
        }
        let session_id = self.secrets.redact(session_id);
        Ok(self
            .conn
            .query_row(
                "SELECT digest, upto, state FROM session_folds
                 WHERE session_id = ?1 AND host = ?2 AND digest = ?3",
                params![session_id, host, digest],
                |r| {
                    Ok(Cached {
                        digest: r.get(0)?,
                        upto: EventId(r.get(1)?),
                        state: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Store `cached` for `session_id` on `host` under its digest. Only a
    /// later `upto` replaces a row, so a slower concurrent guard cannot move
    /// it back. The session keeps its 16 most recently written rows on `host`.
    pub fn set_session_cache(
        &self,
        session_id: &str,
        host: &str,
        cached: &Cached,
    ) -> Result<(), StoreError> {
        self.conn.execute_batch(TABLE)?;
        let session_id = self.secrets.redact(session_id);
        self.conn.execute(
            "INSERT INTO session_folds (session_id, host, digest, upto, state, touched)
             VALUES (?1, ?2, ?3, ?4, ?5,
                     (SELECT IFNULL(MAX(touched), 0) + 1 FROM session_folds))
             ON CONFLICT (session_id, host, digest) DO UPDATE SET
                 upto = excluded.upto, state = excluded.state, touched = excluded.touched
             WHERE excluded.upto > session_folds.upto",
            params![session_id, host, cached.digest, cached.upto.0, cached.state],
        )?;
        self.conn.execute(
            "DELETE FROM session_folds WHERE session_id = ?1 AND host = ?2 AND touched NOT IN
                 (SELECT touched FROM session_folds WHERE session_id = ?1 AND host = ?2
                  ORDER BY touched DESC LIMIT ?3)",
            params![session_id, host, ROWS_PER_SESSION],
        )?;
        Ok(())
    }

    /// [`Store::set_session_cache`], without waiting for the database's write
    /// lock: when another connection holds it, nothing is written and this
    /// returns `Ok(false)`. The cache is only a shortcut, and the guard that
    /// writes it is about to wait for the same lock to record its call, so it
    /// must not wait twice. A skipped write leaves the older row, which the
    /// next fold reads on from (the row only moves forward, never back).
    pub fn try_set_session_cache(
        &self,
        session_id: &str,
        host: &str,
        cached: &Cached,
    ) -> Result<bool, StoreError> {
        self.conn.busy_timeout(Duration::ZERO)?;
        let written = self.set_session_cache(session_id, host, cached);
        // Restored whatever happened: a later write on this handle (the
        // guard's record) waits for the lock as usual.
        self.conn
            .busy_timeout(Duration::from_millis(super::BUSY_TIMEOUT_MS))?;
        match written {
            Ok(()) => Ok(true),
            Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(error, _)))
                if matches!(
                    error.code,
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}
