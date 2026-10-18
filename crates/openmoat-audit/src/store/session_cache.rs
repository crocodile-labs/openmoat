//! What a session's earlier calls folded to, so that a guard call late in a
//! long session reads only the events recorded since (#570).
//!
//! The cache is a convenience beside the events, never a source of truth: it
//! is outside the hash chain, a caller compares its `digest` with what the
//! fold depends on and folds from the first event when they differ, and a
//! cache that cannot be read is treated as absent. The table is created on
//! first write, so the schema version (and older builds' view of the
//! database) is unchanged.

use std::time::Duration;

use rusqlite::{ErrorCode, OptionalExtension as _, params};

use super::{EventId, Store, StoreError, row_to_event};
use crate::store::Event;

const TABLE: &str = "CREATE TABLE IF NOT EXISTS session_cache (
    session_id  TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    digest      TEXT    NOT NULL,
    upto        INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    PRIMARY KEY (session_id, host)
)";

/// A session's folded state as of event `upto`, computed under `digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    /// What the fold depended on (the caller's own spelling); a different
    /// digest means the state no longer applies.
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
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE session_id = ?1 AND id > ?2 ORDER BY id",
            self.select()
        ))?;
        let session_id = self.secrets.redact(session_id);
        let rows = stmt.query_map(params![session_id, after.0], row_to_event)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// The cached state of `session_id` on `host`, if one was written.
    pub fn session_cache(
        &self,
        session_id: &str,
        host: &str,
    ) -> Result<Option<Cached>, StoreError> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_cache'",
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
                "SELECT digest, upto, state FROM session_cache WHERE session_id = ?1 AND host = ?2",
                params![session_id, host],
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

    /// Store `cached` for `session_id` on `host`. A row computed under another
    /// digest is replaced; under the same digest only a later `upto` wins, so a
    /// slower concurrent guard cannot move the cache back.
    pub fn set_session_cache(
        &self,
        session_id: &str,
        host: &str,
        cached: &Cached,
    ) -> Result<(), StoreError> {
        self.conn.execute_batch(TABLE)?;
        let session_id = self.secrets.redact(session_id);
        self.conn.execute(
            "INSERT INTO session_cache (session_id, host, digest, upto, state)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (session_id, host) DO UPDATE SET
                 digest = excluded.digest, upto = excluded.upto, state = excluded.state
             WHERE excluded.digest != session_cache.digest OR excluded.upto > session_cache.upto",
            params![session_id, host, cached.digest, cached.upto.0, cached.state],
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
