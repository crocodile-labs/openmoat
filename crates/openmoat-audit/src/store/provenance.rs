//! File provenance (ADR-029): which session last wrote a file, whether it had
//! read untrusted content then, and which sessions later read such a file.
//!
//! Rows are appended after the event of the call they come from and never
//! changed (the schema's triggers refuse an update or a delete): the newest
//! write row of a path is its provenance, so a clean rewrite is a new row, not
//! an edit. Lookups go through an index on the path or on the session.

use std::fmt;
use std::str::FromStr;

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::{EventId, Store, StoreError, now_ms};

/// What one provenance row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceKind {
    /// A session that had read untrusted content wrote the file.
    TaintedWrite,
    /// A session that had read no untrusted content replaced the whole file:
    /// what it holds now is not attacker-influenced, so it is clean again.
    CleanWrite,
    /// A session read or ran a file whose newest write was tainted, and still
    /// holds what that write wrote; the session is tainted from then on.
    TaintedRead,
}

impl ProvenanceKind {
    /// The stored spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TaintedWrite => "tainted-write",
            Self::CleanWrite => "clean-write",
            Self::TaintedRead => "tainted-read",
        }
    }
}

impl fmt::Display for ProvenanceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProvenanceKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tainted-write" => Ok(Self::TaintedWrite),
            "clean-write" => Ok(Self::CleanWrite),
            "tainted-read" => Ok(Self::TaintedRead),
            other => Err(format!("unknown provenance kind `{other}`")),
        }
    }
}

/// A row to append. Its texts are redacted as an event's are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProvenance {
    /// What the row records.
    pub kind: ProvenanceKind,
    /// The file, in the caller's lookup form.
    pub path: String,
    /// Lowercase hex SHA-256 of the content written, when the call sent the
    /// whole file; `None` when it is not known (`Edit`, a shell write).
    pub sha256: Option<String>,
    /// For a write, the untrusted content the session had read; for a read,
    /// why the session is now tainted.
    pub source: String,
}

/// The newest write row of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProvenance {
    /// The event of the call that wrote it.
    pub event_id: EventId,
    /// The host of the session that wrote it.
    pub host: String,
    /// The session that wrote it.
    pub session_id: String,
    /// Whether that session had read untrusted content.
    pub tainted: bool,
    /// The hash of what it wrote, when known.
    pub sha256: Option<String>,
    /// The untrusted content that session had read (empty for a clean write).
    pub source: String,
}

/// What reading files of tainted provenance did to one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// Why the session is tainted, from its first such read.
    pub source: String,
    /// The event of its latest such read.
    pub last_event: EventId,
    /// When that read was recorded (ms since the epoch).
    pub last_ts_ms: i64,
}

impl Store {
    /// Whether any provenance row exists; when none does, a session that read
    /// no untrusted content has nothing to look up or record.
    pub fn has_provenance(&self) -> Result<bool, StoreError> {
        if !self.provenance {
            return Ok(false);
        }
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM provenance LIMIT 1", [], |r| r.get(0))
            .optional()?;
        Ok(found.is_some())
    }

    /// The newest write row of `path`, if any.
    pub fn file_provenance(&self, path: &str) -> Result<Option<FileProvenance>, StoreError> {
        if !self.provenance {
            return Ok(None);
        }
        let path = self.secrets.redact(path);
        let row = self
            .conn
            .query_row(
                "SELECT event_id, host, session_id, kind, sha256, source FROM provenance
                 WHERE path = ?1 AND kind != 'tainted-read' ORDER BY id DESC LIMIT 1",
                params![path],
                |r| {
                    let kind: String = r.get(3)?;
                    Ok(FileProvenance {
                        event_id: EventId(r.get(0)?),
                        host: r.get(1)?,
                        session_id: r.get(2)?,
                        // an unknown kind is read as tainted: never less strict
                        tainted: kind.parse() != Ok(ProvenanceKind::CleanWrite),
                        sha256: r.get(4)?,
                        source: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// What reads of tainted files did to `session_id` on `host`, if any.
    pub fn exposure(&self, session_id: &str, host: &str) -> Result<Option<Exposure>, StoreError> {
        if !self.provenance {
            return Ok(None);
        }
        let session_id = self.secrets.redact(session_id);
        let host = self.secrets.redact(host);
        let row: (Option<String>, Option<i64>, Option<i64>) = self.conn.query_row(
            "SELECT (SELECT source FROM provenance
                     WHERE session_id = ?1 AND host = ?2 AND kind = 'tainted-read'
                     ORDER BY id LIMIT 1),
                    MAX(event_id), MAX(ts_ms)
             FROM provenance WHERE session_id = ?1 AND host = ?2 AND kind = 'tainted-read'",
            params![session_id, host],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(match row {
            (Some(source), Some(event), Some(ts)) => Some(Exposure {
                source,
                last_event: EventId(event),
                last_ts_ms: ts,
            }),
            _ => None,
        })
    }

    /// Append `rows`, which the call recorded as `event` of `session_id` on
    /// `host` produced, in one transaction.
    pub fn add_provenance(
        &self,
        event: EventId,
        host: &str,
        session_id: &str,
        rows: &[NewProvenance],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let secrets = &self.secrets;
        let host = secrets.redact(host);
        let session_id = secrets.redact(session_id);
        let ts_ms = now_ms();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        for row in rows {
            tx.execute(
                "INSERT INTO provenance (event_id, ts_ms, host, session_id, kind, path, sha256, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.0,
                    ts_ms,
                    host,
                    session_id,
                    row.kind.as_str(),
                    secrets.redact(&row.path),
                    row.sha256,
                    secrets.redact(&row.source),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
