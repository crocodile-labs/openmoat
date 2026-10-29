//! The files each session wrote (ADR-039), so `moat guard` can tell when a
//! session runs code it wrote itself.
//!
//! One row per file, host and session: a session that writes a file again
//! replaces its row, which then names the newer event. Unlike file provenance
//! (`provenance.rs`) the rows are not a record of what happened but a lookup
//! for running sessions, so they are bounded: adding a row removes those
//! older than [`MAX_AGE_MS`] and all but the newest [`MAX_ROWS`] (every
//! [`PRUNE_EVERY`] rows). A file whose
//! row was removed counts as one the session did not write, as a file written
//! before OpenMoat recorded writes does.

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::{EventId, Store, StoreError, now_ms};

/// Rows older than this are removed: 30 days, longer than an agent session
/// is resumed in practice.
pub(super) const MAX_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// At most this many rows are kept, the newest first; about 15 MB of paths.
pub(super) const MAX_ROWS: i64 = 100_000;

/// Rows past the bounds are removed when a new row's id passes a multiple of this.
pub(super) const PRUNE_EVERY: i64 = 64;

/// A file a call writes. Its texts are redacted as an event's are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionWrite {
    /// The file, in the caller's lookup form.
    pub path: String,
    /// Lowercase hex SHA-256 of what the call writes, when it sends the whole
    /// file (`Write`); `None` when it is not known (`Edit`, a shell write).
    pub sha256: Option<String>,
}

/// The newest write of a file by one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The file, as it was looked up.
    pub path: String,
    /// The event of the call that last wrote it.
    pub event_id: EventId,
    /// When that call was recorded (ms since the epoch).
    pub ts_ms: i64,
    /// The hash of what it wrote, when known.
    pub sha256: Option<String>,
}

impl Store {
    /// Record that the call recorded as `event` of `session_id` on `host`
    /// writes `writes`, in one transaction, and remove rows past the bounds.
    pub fn add_session_writes(
        &self,
        event: EventId,
        host: &str,
        session_id: &str,
        writes: &[SessionWrite],
    ) -> Result<(), StoreError> {
        if writes.is_empty() || !self.session_writes() {
            return Ok(());
        }
        let secrets = &self.secrets;
        let host = secrets.redact(host);
        let session_id = secrets.redact(session_id);
        let ts_ms = now_ms();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        for write in writes {
            // `REPLACE` deletes the old row and adds one with a new id, so the
            // newest rows have the highest ids for the row limit.
            tx.execute(
                "INSERT OR REPLACE INTO session_writes (event_id, ts_ms, host, session_id, path, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event.0,
                    ts_ms,
                    host,
                    session_id,
                    secrets.redact(&write.path),
                    write.sha256
                ],
            )?;
        }
        // Pruning scans the age index; once every PRUNE_EVERY rows keeps the
        // table within its bounds at a fraction of the cost.
        let newest = tx.last_insert_rowid();
        if newest % PRUNE_EVERY < i64::try_from(writes.len()).unwrap_or(i64::MAX) {
            tx.execute(
                "DELETE FROM session_writes WHERE ts_ms < ?1",
                params![ts_ms.saturating_sub(MAX_AGE_MS)],
            )?;
            tx.execute(
                "DELETE FROM session_writes WHERE id <= ?1 - ?2",
                params![newest, MAX_ROWS],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether `session_id` on `host` wrote any file: one probe of the index.
    pub fn session_wrote_any(&self, host: &str, session_id: &str) -> Result<bool, StoreError> {
        if !self.session_writes() {
            return Ok(false);
        }
        let found: Option<i64> = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM session_writes WHERE host = ?1 AND session_id = ?2 LIMIT 1",
            )?
            .query_row(
                params![self.secrets.redact(host), self.secrets.redact(session_id)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Which of `paths` `session_id` on `host` wrote, each with its newest write.
    pub fn session_wrote(
        &self,
        host: &str,
        session_id: &str,
        paths: &[String],
    ) -> Result<Vec<Written>, StoreError> {
        if paths.is_empty() || !self.session_writes() {
            return Ok(Vec::new());
        }
        let secrets = &self.secrets;
        let host = secrets.redact(host);
        let session_id = secrets.redact(session_id);
        let mut stmt = self.conn.prepare_cached(
            "SELECT event_id, ts_ms, sha256 FROM session_writes
             WHERE host = ?1 AND session_id = ?2 AND path = ?3",
        )?;
        let mut found = Vec::new();
        for path in paths {
            let mut rows = stmt.query(params![host, session_id, secrets.redact(path)])?;
            if let Some(row) = rows.next()? {
                found.push(Written {
                    path: path.clone(),
                    event_id: EventId(row.get(0)?),
                    ts_ms: row.get(1)?,
                    sha256: row.get(2)?,
                });
            }
        }
        Ok(found)
    }
}
