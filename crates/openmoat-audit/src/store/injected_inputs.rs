//! Injected input (ADR-057): keyed fingerprints of the distinctive parts of
//! untrusted content each session read, so `openmoat guard` can tell when a
//! later call acts on one of them.
//!
//! A row holds a fingerprint and the source that brought it in
//! (`fetch https://docs.example/page`), never the text it was computed from;
//! the caller computes fingerprints with a key the store does not hold. Like
//! the files sessions wrote (`session_writes.rs`), the rows are a lookup for
//! running sessions, not a record, so they are bounded: a session keeps at
//! most [`MAX_PER_SESSION`] and later ones are dropped, and adding rows
//! removes those older than [`MAX_AGE_MS`] and all but the newest
//! [`MAX_ROWS`] (every [`PRUNE_EVERY`] rows).

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::{Store, StoreError, now_ms};

/// Rows older than this are removed: 30 days, as for the files sessions wrote.
pub(super) const MAX_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// The most fingerprints one session keeps; about 600 KB.
pub const MAX_PER_SESSION: i64 = 4096;

/// At most this many rows are kept, the newest first.
pub(super) const MAX_ROWS: i64 = 200_000;

/// Rows past the bounds are removed when a new row's id passes a multiple of this.
pub(super) const PRUNE_EVERY: i64 = 64;

/// The longest source kept with a row, in characters, after redaction.
pub const MAX_SOURCE_LEN: usize = 200;

/// One fingerprint to keep. The source is redacted as an event's texts are,
/// then cut to [`MAX_SOURCE_LEN`]: redaction sees the whole of it, so a
/// credential the cut would split (`Authorization="Bearer …"`) is still found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInjected {
    /// The caller's keyed fingerprint of one token (lowercase hex).
    pub fingerprint: String,
    /// What brought the token in.
    pub source: String,
}

impl Store {
    /// Keep `rows` for `session_id` on `host`, in one transaction: a
    /// fingerprint the session already has keeps its first source, and rows
    /// past [`MAX_PER_SESSION`] are dropped. Returns how many were added.
    pub fn add_injected_inputs(
        &self,
        host: &str,
        session_id: &str,
        rows: &[NewInjected],
    ) -> Result<usize, StoreError> {
        if rows.is_empty() || !self.injected_inputs() {
            return Ok(0);
        }
        let secrets = &self.secrets;
        let host = secrets.redact(host);
        let session_id = secrets.redact(session_id);
        let ts_ms = now_ms();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let held: i64 = tx.query_row(
            "SELECT COUNT(*) FROM injected_inputs WHERE host = ?1 AND session_id = ?2",
            params![host, session_id],
            |r| r.get(0),
        )?;
        let mut room = MAX_PER_SESSION.saturating_sub(held);
        let mut added = 0usize;
        let mut newest = 0;
        for row in rows {
            if room <= 0 {
                break;
            }
            let changed = tx.execute(
                "INSERT OR IGNORE INTO injected_inputs (ts_ms, host, session_id, fingerprint, source)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts_ms, host, session_id, row.fingerprint, cut(&secrets.redact(&row.source))],
            )?;
            if changed > 0 {
                room -= 1;
                added += 1;
                newest = tx.last_insert_rowid();
            }
        }
        if added > 0 && newest % PRUNE_EVERY < i64::try_from(added).unwrap_or(i64::MAX) {
            tx.execute(
                "DELETE FROM injected_inputs WHERE ts_ms < ?1",
                params![ts_ms.saturating_sub(MAX_AGE_MS)],
            )?;
            tx.execute(
                "DELETE FROM injected_inputs WHERE id <= ?1 - ?2",
                params![newest, MAX_ROWS],
            )?;
        }
        tx.commit()?;
        Ok(added)
    }

    /// Whether `session_id` on `host` keeps any fingerprint: one probe of the
    /// index, so a session that read nothing untrusted pays nothing more.
    pub fn has_injected_inputs(&self, host: &str, session_id: &str) -> Result<bool, StoreError> {
        if !self.injected_inputs() {
            return Ok(false);
        }
        let found: Option<i64> = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM injected_inputs WHERE host = ?1 AND session_id = ?2 LIMIT 1",
            )?
            .query_row(
                params![self.secrets.redact(host), self.secrets.redact(session_id)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The source of `fingerprint` in `session_id` on `host`, if it keeps it.
    pub fn injected_source(
        &self,
        host: &str,
        session_id: &str,
        fingerprint: &str,
    ) -> Result<Option<String>, StoreError> {
        if !self.injected_inputs() {
            return Ok(None);
        }
        let source = self
            .conn
            .prepare_cached(
                "SELECT source FROM injected_inputs
                 WHERE host = ?1 AND session_id = ?2 AND fingerprint = ?3",
            )?
            .query_row(
                params![
                    self.secrets.redact(host),
                    self.secrets.redact(session_id),
                    fingerprint
                ],
                |r| r.get(0),
            )
            .optional()?;
        Ok(source)
    }
}

/// `text`, cut to [`MAX_SOURCE_LEN`] characters with `…` after a cut.
fn cut(text: &str) -> String {
    if text.chars().count() <= MAX_SOURCE_LEN {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(MAX_SOURCE_LEN).collect();
    short.push('…');
    short
}
