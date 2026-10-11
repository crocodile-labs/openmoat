//! The audit database: schema, writes and row decoding.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use openmoat_core::{Action, Decision, Verdict};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::KnownSecrets;

mod chain;
mod export;
mod export_verify;
mod schema;

pub use chain::{BreakKind, ChainBreak, ChainReport, GENESIS};
pub use export::{ExportFilter, ExportFormat, ExportedEvent};
pub use export_verify::{AnchorCheck, ExportBreak, ExportReport, verify_export};

const BUSY_TIMEOUT_MS: u64 = 2000;

/// Why the audit database could not be used. `guard` denies on any of these.
///
/// Messages include their cause, so no variant also exposes it as `source`:
/// a chained report (`{:#}`) would print it twice.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// `SQLite` failed (open, query, constraint).
    #[error("audit database: {0}")]
    Sqlite(rusqlite::Error),
    /// The database was written by a newer `moat`.
    #[error(
        "audit database schema version {found} is newer than this build supports ({supported})"
    )]
    SchemaTooNew {
        /// Schema version in the file.
        found: i64,
        /// Schema version this build supports.
        supported: i64,
    },
    /// A `moat show <id>` argument is not a hex event id.
    #[error("invalid event id `{0}`; expected hex such as 1f")]
    InvalidId(String),
    /// An event could not be encoded for storage.
    #[error("encoding event: {0}")]
    Encode(serde_json::Error),
    /// The database file could not be created or restricted.
    #[error("audit database file: {0}")]
    Io(std::io::Error),
    /// The known secret values are too large to match together (`KnownSecrets`).
    #[error("the known secret values are too large to mask")]
    Secrets,
    /// A cell of an exported event does not decode (verdict, rules or reasons).
    #[error("exported event {id}: {reason}")]
    Decode {
        /// The event.
        id: EventId,
        /// What does not decode.
        reason: String,
    },
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Encode(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Row id, shown, parsed and serialised as lowercase hex (`moat show 1f`,
/// `"id": "1f"`). The integers older builds serialised still deserialise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "WireId")]
pub struct EventId(pub i64);

impl From<EventId> for String {
    fn from(id: EventId) -> Self {
        id.to_string()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireId {
    Hex(String),
    Row(i64),
}

impl TryFrom<WireId> for EventId {
    type Error = StoreError;

    fn try_from(wire: WireId) -> Result<Self, Self::Error> {
        match wire {
            WireId::Hex(text) => text.parse(),
            WireId::Row(id) => Ok(Self(id)),
        }
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for EventId {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.trim().trim_start_matches('#');
        i64::from_str_radix(digits, 16)
            .ok()
            .filter(|id| *id > 0)
            .map(EventId)
            .ok_or_else(|| StoreError::InvalidId(s.to_owned()))
    }
}

/// What a caller records. Secrets are redacted before storage.
#[derive(Debug, Clone)]
pub struct NewEvent<'a> {
    /// Host id.
    pub host: &'a str,
    /// Host session id.
    pub session_id: &'a str,
    /// Host call id, when sent.
    pub call_id: Option<&'a str>,
    /// Working directory, when sent.
    pub cwd: Option<&'a str>,
    /// Tool name as the host spells it.
    pub tool: &'a str,
    /// The governed action; `None` for an ungoverned tool.
    pub action: Option<&'a Action>,
    /// The decision taken.
    pub decision: &'a Decision,
    /// Time spent deciding, in microseconds.
    pub latency_us: u64,
}

/// A stored decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Row id.
    pub id: EventId,
    /// Time recorded (ms since the epoch).
    pub ts_ms: i64,
    /// Host id.
    pub host: String,
    /// Host session id.
    pub session_id: String,
    /// Host call id, when sent.
    pub call_id: Option<String>,
    /// Working directory, when sent.
    pub cwd: Option<String>,
    /// Tool name as the host spells it.
    pub tool: String,
    /// The governed action (redacted); `None` for an ungoverned tool.
    pub action: Option<Action>,
    /// The stored action could not be decoded (a corrupt or hand-edited row);
    /// `action` is then `None` although the tool was governed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub action_unreadable: bool,
    /// The verdict.
    pub verdict: Verdict,
    /// Rule ids that produced the verdict.
    pub rules: Vec<String>,
    /// One redacted reason per rule.
    pub reasons: Vec<String>,
    /// Time spent deciding, in microseconds.
    pub latency_us: i64,
    /// Hash of the event before it in the chain; `None` for an event written
    /// before the chain existed.
    #[serde(default)]
    pub prev_hash: Option<String>,
    /// This event's chain hash (lowercase hex SHA-256, see `verify_chain`);
    /// `None` for an event written before the chain existed.
    #[serde(default)]
    pub hash: Option<String>,
}

/// A handle to the audit database.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
    /// The schema has the chain columns. Only a read-only handle on a database
    /// no newer build has opened yet lacks them.
    chained: bool,
    /// Masked in every event this handle records.
    secrets: KnownSecrets,
}

impl Store {
    /// Open (creating if needed) the audit database at `path`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        create_owner_only(path)?;
        let conn = Connection::open_with_flags(path, flags)?;
        Self::initialise(conn)
    }

    /// Writable handle to an existing database. Unlike [`Store::open`] it does
    /// not create one, so a deleted audit log is an error rather than a silent
    /// fresh start.
    pub fn open_existing(path: &Path) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        Self::initialise(conn)
    }

    /// Read-only handle; fails if the database does not exist.
    pub fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
        let chained = schema::version(&conn)? >= 2;
        Ok(Self {
            conn,
            chained,
            secrets: KnownSecrets::default(),
        })
    }

    /// A throwaway database for tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::initialise(Connection::open_in_memory()?)
    }

    fn initialise(conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        schema::migrate(&conn)?;
        Ok(Self {
            conn,
            chained: true,
            secrets: KnownSecrets::default(),
        })
    }

    /// This handle, masking `secrets` in every event it records from now on.
    #[must_use]
    pub fn with_secrets(self, secrets: KnownSecrets) -> Self {
        Self { secrets, ..self }
    }

    /// Append one decision and return its id.
    pub fn record(&self, event: &NewEvent<'_>) -> Result<EventId, StoreError> {
        self.record_at(event, now_ms())
    }

    /// Append one decision with an explicit timestamp (milliseconds since the epoch).
    pub fn record_at(&self, event: &NewEvent<'_>, ts_ms: i64) -> Result<EventId, StoreError> {
        // Every text is redacted here, in one place, so each writer (guard,
        // proxy) and the export built from the rows are covered. That includes
        // the host, session and call ids and the tool name: a host payload or
        // an agent can put a secret in any of them. [`Store::session`] redacts
        // its argument the same way, so a session is still found by its id.
        let secrets = &self.secrets;
        let host = secrets.redact(event.host);
        let session_id = secrets.redact(event.session_id);
        let call_id = event.call_id.map(|c| secrets.redact(c));
        let tool = secrets.redact(event.tool);
        let action_json = match event.action {
            Some(action) => {
                serde_json::to_string(&secrets.redact_value(serde_json::to_value(action)?))?
            }
            None => "null".to_owned(),
        };
        let reasons: Vec<String> = event
            .decision
            .reasons
            .iter()
            .map(|r| secrets.redact(r))
            .collect();
        let cwd = event.cwd.map(|c| secrets.redact(c));
        let rules = serde_json::to_string(&event.decision.rules)?;
        let reasons = serde_json::to_string(&reasons)?;
        // Reading the newest hash and appending must be one step, or two
        // concurrent `guard` processes would link to the same event and fork
        // the chain. `BEGIN IMMEDIATE` takes the write lock up front (waiting up
        // to the busy timeout); dropping the transaction on error rolls back.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let (id, prev_hash) = chain::next_link(&tx)?;
        let fields = chain::Fields {
            id,
            ts_ms,
            host: &host,
            session_id: &session_id,
            call_id: call_id.as_deref(),
            cwd: cwd.as_deref(),
            tool: &tool,
            action: &action_json,
            verdict: event.decision.verdict.as_str(),
            rules: &rules,
            reasons: &reasons,
            latency_us: i64::try_from(event.latency_us).unwrap_or(i64::MAX),
            prev_hash: &prev_hash,
        };
        tx.execute(
            "INSERT INTO events (id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                fields.id,
                fields.ts_ms,
                fields.host,
                fields.session_id,
                fields.call_id,
                fields.cwd,
                fields.tool,
                fields.action,
                fields.verdict,
                fields.rules,
                fields.reasons,
                fields.latency_us,
                fields.prev_hash,
                fields.hash(),
            ],
        )?;
        tx.commit()?;
        Ok(EventId(id))
    }

    /// One event by id.
    pub fn get(&self, id: EventId) -> Result<Option<Event>, StoreError> {
        self.conn
            .query_row(
                &format!("{} WHERE id = ?1", self.select()),
                params![id.0],
                row_to_event,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("{} ORDER BY id DESC LIMIT ?1", self.select()))?;
        let rows = stmt.query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            row_to_event,
        )?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// All events of one session, oldest first. `session_id` is matched as
    /// [`Store::record`] stored it, redacted.
    pub fn session(&self, session_id: &str) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE session_id = ?1 ORDER BY id",
            self.select()
        ))?;
        let session_id = self.secrets.redact(session_id);
        let rows = stmt.query_map(params![session_id], row_to_event)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Number of stored events.
    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or_default())
    }
}

const SELECT_CHAINED: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, prev_hash, hash FROM events";
const SELECT_UNCHAINED: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, NULL, NULL FROM events";

impl Store {
    /// The event query for this database's schema, for [`row_to_event`].
    pub(crate) fn select(&self) -> &'static str {
        if self.chained {
            SELECT_CHAINED
        } else {
            SELECT_UNCHAINED
        }
    }
}

pub(crate) fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    fn decode<T: serde::de::DeserializeOwned>(
        row: &rusqlite::Row<'_>,
        index: usize,
    ) -> rusqlite::Result<T> {
        let text: String = row.get(index)?;
        serde_json::from_str(&text).map_err(|e| json_error(e, row))
    }
    // A row whose action cell cannot be decoded (corrupt or hand-edited) still
    // reports its verdict, rules and reasons instead of failing the whole
    // query, and says that its action is unreadable.
    let decoded: Result<Option<Action>, _> = decode(row, 7);
    let action_unreadable = decoded.is_err();
    let verdict_text: String = row.get(8)?;
    let verdict = verdict_text.parse::<Verdict>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Event {
        id: EventId(row.get(0)?),
        ts_ms: row.get(1)?,
        host: row.get(2)?,
        session_id: row.get(3)?,
        call_id: row.get(4)?,
        cwd: row.get(5)?,
        tool: row.get(6)?,
        action: decoded.unwrap_or(None),
        action_unreadable,
        verdict,
        rules: decode(row, 9)?,
        reasons: decode(row, 10)?,
        latency_us: row.get(11)?,
        prev_hash: row.get(12)?,
        hash: row.get(13)?,
    })
}

fn json_error(e: serde_json::Error, row: &rusqlite::Row<'_>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        row.as_ref().column_count(),
        rusqlite::types::Type::Text,
        Box::new(e),
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Create the database file owner-only before `SQLite` opens it. `SQLite` gives the
/// `-wal` and `-shm` files the main file's permissions, so the whole log stays
/// unreadable to other users; an existing file is tightened.
fn create_owner_only(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        options.open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    options.open(path)?;
    Ok(())
}

#[cfg(test)]
mod tests;
