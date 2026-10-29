//! The hash chain over audit events: canonical encoding, hashing and verification.
//!
//! Each event stores `prev_hash` (the `hash` of the event before it) and `hash`,
//! the lowercase hex SHA-256 of the event's canonical encoding (below). Editing,
//! deleting or reordering an event in the middle of the log breaks a link that
//! [`Store::verify_chain`] reports. The chain is unkeyed: someone who can write
//! the file can recompute every hash after an edit, and deleting the newest
//! events leaves a valid shorter chain. Detecting either needs the head hash
//! recorded outside the file (`docs/THREAT_MODEL.md`).
//!
//! # Canonical encoding, version 1
//!
//! The concatenation, in this order, of:
//!
//! 1. the domain tag `moat-audit-chain-v1` as a string;
//! 2. `id`, `ts_ms` as integers;
//! 3. `host`, `session_id` as strings;
//! 4. `call_id`, `cwd` as optional strings;
//! 5. `tool`, `action`, `verdict`, `rules`, `reasons` as strings: the cells exactly
//!    as stored, so `action`, `rules` and `reasons` are their redacted JSON text;
//! 6. `latency_us` as an integer;
//! 7. `prev_hash` as a string.
//!
//! An integer is 8 bytes, big-endian two's complement. A string is its UTF-8 length
//! as 8 bytes big-endian, then its bytes. An optional string is the byte `0x00`
//! when absent, or `0x01` followed by the string. Length prefixes make the encoding
//! unambiguous; hashing stored cells rather than re-serialised values keeps it
//! independent of how a later build serialises an `Action`.
//!
//! The first chained event's `prev_hash` is [`GENESIS`]. A change to this encoding
//! needs a new domain tag; events already written keep verifying under v1.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Store, StoreError};

/// `prev_hash` of the first chained event: 64 zeros.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const DOMAIN: &str = "moat-audit-chain-v1";

/// The stored cells of one event, in the form the chain hashes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields<'a> {
    pub id: i64,
    pub ts_ms: i64,
    pub host: &'a str,
    pub session_id: &'a str,
    pub call_id: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub tool: &'a str,
    pub action: &'a str,
    pub verdict: &'a str,
    pub rules: &'a str,
    pub reasons: &'a str,
    pub latency_us: i64,
    pub prev_hash: &'a str,
}

impl Fields<'_> {
    /// The canonical encoding described in the module documentation.
    pub(crate) fn encode(&self) -> Vec<u8> {
        fn int(out: &mut Vec<u8>, value: i64) {
            out.extend_from_slice(&value.to_be_bytes());
        }
        fn text(out: &mut Vec<u8>, value: &str) {
            // usize → u64 is lossless on every supported target.
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        fn optional(out: &mut Vec<u8>, value: Option<&str>) {
            match value {
                None => out.push(0),
                Some(value) => {
                    out.push(1);
                    text(out, value);
                }
            }
        }
        let mut out = Vec::with_capacity(256);
        text(&mut out, DOMAIN);
        int(&mut out, self.id);
        int(&mut out, self.ts_ms);
        text(&mut out, self.host);
        text(&mut out, self.session_id);
        optional(&mut out, self.call_id);
        optional(&mut out, self.cwd);
        for cell in [
            self.tool,
            self.action,
            self.verdict,
            self.rules,
            self.reasons,
        ] {
            text(&mut out, cell);
        }
        int(&mut out, self.latency_us);
        text(&mut out, self.prev_hash);
        out
    }

    /// Lowercase hex SHA-256 of [`Fields::encode`].
    pub(crate) fn hash(&self) -> String {
        Sha256::digest(self.encode())
            .iter()
            .fold(String::with_capacity(64), |mut hex, b| {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02x}");
                hex
            })
    }
}

/// Why the chain breaks at an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BreakKind {
    /// The event's contents no longer match its hash: it was edited.
    Edited,
    /// The event's `prev_hash` is not the previous event's hash: an event before
    /// it was deleted or inserted, or events were reordered.
    Unlinked,
    /// The event has no hash although it was written after the chain started.
    Unhashed,
    /// A cell does not have the type the schema gives it.
    Unreadable,
}

impl BreakKind {
    /// A short explanation for people.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Edited => "its contents do not match its hash (edited)",
            Self::Unlinked => {
                "it does not link to the event before it (an event was deleted, inserted or reordered)"
            }
            Self::Unhashed => "it has no hash although it was written after the chain started",
            Self::Unreadable => "a cell has the wrong type (edited)",
        }
    }
}

/// The first broken link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBreak {
    /// Row id of the first event that fails verification.
    pub id: super::EventId,
    /// Why it fails.
    pub kind: BreakKind,
}

/// The outcome of [`Store::verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    /// Events read, up to and including the first broken one.
    pub events: u64,
    /// Events written before the chain existed (by a build without it). They are
    /// not protected.
    pub unchained: u64,
    /// Hash of the last verified event; record it elsewhere to detect a later
    /// truncation or rewrite.
    pub head: Option<String>,
    /// The first broken link, if any.
    pub broken: Option<ChainBreak>,
}

/// Every stored cell of an event, in the order [`read_row`] expects.
pub(super) const ROWS: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, prev_hash, hash FROM events";

/// One event's cells exactly as stored.
pub(super) struct Row {
    pub id: i64,
    pub ts_ms: i64,
    /// `host`, `session_id`, `tool`, `action`, `verdict`, `rules`, `reasons`.
    pub cells: [String; 7],
    pub call_id: Option<String>,
    pub cwd: Option<String>,
    pub latency_us: i64,
    pub prev_hash: Option<String>,
    pub hash: Option<String>,
}

pub(super) fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: row.get(0)?,
        ts_ms: row.get(1)?,
        cells: [
            row.get(2)?,
            row.get(3)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
        ],
        call_id: row.get(4)?,
        cwd: row.get(5)?,
        latency_us: row.get(11)?,
        prev_hash: row.get(12)?,
        hash: row.get(13)?,
    })
}

impl Row {
    fn fields<'a>(&'a self, prev_hash: &'a str) -> Fields<'a> {
        let [host, session_id, tool, action, verdict, rules, reasons] = &self.cells;
        Fields {
            id: self.id,
            ts_ms: self.ts_ms,
            host,
            session_id,
            call_id: self.call_id.as_deref(),
            cwd: self.cwd.as_deref(),
            tool,
            action,
            verdict,
            rules,
            reasons,
            latency_us: self.latency_us,
            prev_hash,
        }
    }
}

impl Store {
    /// Verify the whole chain, oldest event first, and stop at the first broken
    /// link. Events from before the chain existed are counted, not verified.
    pub fn verify_chain(&self) -> Result<ChainReport, StoreError> {
        let mut report = ChainReport {
            events: 0,
            unchained: 0,
            head: None,
            broken: None,
        };
        if !self.chained() {
            report.events = self.count()?;
            report.unchained = report.events;
            return Ok(report);
        }
        let legacy_last_id: i64 = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'legacy_last_id'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!("{ROWS} ORDER BY id"))?;
        let mut rows = stmt.query([])?;
        while let Some(raw) = rows.next()? {
            report.events += 1;
            let id: i64 = raw.get(0)?;
            let kind = match read_row(raw) {
                Err(_) => Some(BreakKind::Unreadable),
                Ok(row) => check(&row, &mut report, legacy_last_id),
            };
            if let Some(kind) = kind {
                report.broken = Some(ChainBreak {
                    id: super::EventId(id),
                    kind,
                });
                break;
            }
        }
        Ok(report)
    }
}

/// The newest chained event: what an anchor records (ADR-031).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    /// Row id of the newest chained event.
    pub id: super::EventId,
    /// When it was recorded (ms since the epoch).
    pub ts_ms: i64,
    /// Its chain hash.
    pub hash: String,
}

impl Store {
    /// The newest event that has a hash, or `None` for a log without one. It is
    /// the chain's head only when [`Store::verify_chain`] finds no break.
    pub fn head(&self) -> Result<Option<ChainHead>, StoreError> {
        if !self.chained() {
            return Ok(None);
        }
        Ok(self
            .conn
            .query_row(
                "SELECT id, ts_ms, hash FROM events WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1",
                [],
                |r| {
                    Ok(ChainHead {
                        id: super::EventId(r.get(0)?),
                        ts_ms: r.get(1)?,
                        hash: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// The stored chain hash of event `id`; `None` when there is no such
    /// event or it has no hash.
    pub fn hash_of(&self, id: super::EventId) -> Result<Option<String>, StoreError> {
        if !self.chained() {
            return Ok(None);
        }
        Ok(self
            .conn
            .query_row(
                "SELECT hash FROM events WHERE id = ?1",
                params![id.0],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }
}

/// Check one row against the chain so far; advance `report.head` when it holds.
fn check(row: &Row, report: &mut ChainReport, legacy_last_id: i64) -> Option<BreakKind> {
    let Some(hash) = &row.hash else {
        if report.head.is_none() && row.id <= legacy_last_id {
            report.unchained += 1;
            return None;
        }
        return Some(BreakKind::Unhashed);
    };
    let expected_prev = report.head.as_deref().unwrap_or(GENESIS);
    if row.prev_hash.as_deref() != Some(expected_prev) {
        return Some(BreakKind::Unlinked);
    }
    if row.fields(expected_prev).hash() != *hash {
        return Some(BreakKind::Edited);
    }
    report.head = Some(hash.clone());
    None
}

/// The `id` and `prev_hash` the next event gets: one past the newest row, linked
/// to its hash (or [`GENESIS`] when there is none, or it predates the chain).
/// Called inside the write transaction, so concurrent writers serialise here.
pub(crate) fn next_link(conn: &rusqlite::Connection) -> Result<(i64, String), StoreError> {
    let last: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1",
            params![],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match last {
        Some((id, hash)) => (
            id.saturating_add(1),
            hash.unwrap_or_else(|| GENESIS.to_owned()),
        ),
        None => (1, GENESIS.to_owned()),
    })
}
