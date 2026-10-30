//! Schema versions and the migration ladder.

use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::StoreError;

/// Schema version this build writes, kept in `PRAGMA user_version`.
pub(super) const SCHEMA_VERSION: i64 = 7;

/// The first version with the hash chain ([`V2`]).
pub(super) const CHAIN_VERSION: i64 = 2;
/// The first version with file provenance ([`V4`]).
pub(super) const PROVENANCE_VERSION: i64 = 4;
/// The first version with the files each session wrote ([`V5`]).
pub(super) const SESSION_WRITES_VERSION: i64 = 5;
/// The first version with the hook's MCP call decisions ([`V6`]).
pub(super) const MCP_TICKETS_VERSION: i64 = 6;
/// The first version that keeps, with each file a session wrote, the state of
/// the file before the write ([`V7`]).
pub(super) const WRITE_BEFORE_VERSION: i64 = 7;

/// Version 1: the events table.
const V1: &str = "
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    call_id     TEXT,
    cwd         TEXT,
    tool        TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('allow','ask','deny')),
    rules       TEXT    NOT NULL,
    reasons     TEXT    NOT NULL,
    latency_us  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts_ms);
";

/// Version 2: the hash chain (`chain.rs`). Rows already present are not hashed:
/// they were written without protection, and hashing them now would vouch for
/// whatever they contain today. `legacy_last_id` records where they end, so a
/// later event without a hash is reported instead of passing as old.
const V2: &str = "
ALTER TABLE events ADD COLUMN prev_hash TEXT;
ALTER TABLE events ADD COLUMN hash TEXT;
CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO meta (key, value) VALUES ('legacy_last_id', COALESCE((SELECT MAX(id) FROM events), 0));
";

/// Version 3: the `defer` verdict (ADR-025). `SQLite` cannot change a `CHECK`, so the
/// table is rebuilt; every row keeps its id, values and hashes, so the chain still
/// verifies.
const V3: &str = "
CREATE TABLE events_v3 (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    call_id     TEXT,
    cwd         TEXT,
    tool        TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('allow','defer','ask','deny')),
    rules       TEXT    NOT NULL,
    reasons     TEXT    NOT NULL,
    latency_us  INTEGER NOT NULL,
    prev_hash   TEXT,
    hash        TEXT
);
INSERT INTO events_v3 (id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules,
                       reasons, latency_us, prev_hash, hash)
    SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules,
           reasons, latency_us, prev_hash, hash FROM events;
DROP TABLE events;
ALTER TABLE events_v3 RENAME TO events;
CREATE INDEX events_session ON events(session_id, id);
CREATE INDEX events_ts ON events(ts_ms);
";

/// Version 4: file provenance (ADR-029, `provenance.rs`). Rows are only
/// appended: the triggers refuse an update or a delete, so a later row, never
/// an edit, is what changes a file's provenance. `IF NOT EXISTS`: a database
/// whose version was set back by hand still migrates.
const V4: &str = "
CREATE TABLE IF NOT EXISTS provenance (
    id          INTEGER PRIMARY KEY,
    event_id    INTEGER NOT NULL,
    ts_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('tainted-write','clean-write','tainted-read')),
    path        TEXT    NOT NULL,
    sha256      TEXT,
    source      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS provenance_path ON provenance(path, id);
CREATE INDEX IF NOT EXISTS provenance_session ON provenance(session_id, host, id);
CREATE TRIGGER IF NOT EXISTS provenance_no_update BEFORE UPDATE ON provenance
    BEGIN SELECT RAISE(ABORT, 'provenance rows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_no_delete BEFORE DELETE ON provenance
    BEGIN SELECT RAISE(ABORT, 'provenance rows are append-only'); END;
";

/// Version 5: the files each session wrote (ADR-039, `session_writes.rs`).
/// One row per file and session, replaced when the session writes the file
/// again; rows older than a bound or past a row limit are removed when a row
/// is added, so the table stays small. `IF NOT EXISTS`, as for [`V4`].
const V5: &str = "
CREATE TABLE IF NOT EXISTS session_writes (
    id          INTEGER PRIMARY KEY,
    event_id    INTEGER NOT NULL,
    ts_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    sha256      TEXT,
    UNIQUE (host, session_id, path)
);
CREATE INDEX IF NOT EXISTS session_writes_ts ON session_writes(ts_ms);
";

/// Version 6: the MCP calls the hook let through, which `openmoat mcp proxy`
/// matches the calls it relays against (ADR-045, `mcp_tickets.rs`). A lookup
/// like [`V5`]: each row is removed when the proxy takes it or when it is an
/// hour old. `IF NOT EXISTS`, as for [`V4`].
const V6: &str = "
CREATE TABLE IF NOT EXISTS mcp_tickets (
    id                INTEGER PRIMARY KEY,
    event_id          INTEGER NOT NULL,
    ts_ms             INTEGER NOT NULL,
    host              TEXT    NOT NULL,
    session_id        TEXT    NOT NULL,
    call_id           TEXT,
    tool              TEXT    NOT NULL,
    arguments_sha256  TEXT    NOT NULL,
    verdict           TEXT    NOT NULL CHECK (verdict IN ('allow','defer','ask'))
);
CREATE INDEX IF NOT EXISTS mcp_tickets_arguments ON mcp_tickets(arguments_sha256, id);
CREATE INDEX IF NOT EXISTS mcp_tickets_ts ON mcp_tickets(ts_ms);
";

/// Version 7: the hash of a file as it was when a call that writes it was
/// decided, beside the hash of what the call writes (`session_writes.rs`), so
/// a later call can tell that the write ran and changed the file (ADR-048).
/// Added to the table only when it is not there yet: a database whose version
/// was set back by hand still migrates, as for [`V4`].
const V7: &str = "
ALTER TABLE session_writes ADD COLUMN before_sha256 TEXT;
";

/// Whether `table` has a column named `column`.
fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, StoreError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The `user_version` of the open database.
pub(super) fn version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?)
}

/// Bring the database to [`SCHEMA_VERSION`]. Several `moat guard` processes may
/// open an old database at once, so the version is re-read under the write lock
/// and each step runs at most once.
pub(super) fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let found = version(conn)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let found = version(&tx)?;
    if found >= SCHEMA_VERSION {
        // Another process migrated first; recheck without the lock.
        drop(tx);
        return migrate(conn);
    }
    if found < 1 {
        tx.execute_batch(V1)?;
    }
    if found < 2 {
        tx.execute_batch(V2)?;
    }
    if found < 3 {
        tx.execute_batch(V3)?;
    }
    if found < 4 {
        tx.execute_batch(V4)?;
    }
    if found < 5 {
        tx.execute_batch(V5)?;
    }
    if found < 6 {
        tx.execute_batch(V6)?;
    }
    if found < 7 && !has_column(&tx, "session_writes", "before_sha256")? {
        tx.execute_batch(V7)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

/// The version-1 schema, for tests that open a database an older build wrote.
#[cfg(test)]
pub(super) fn create_v1(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(V1)?;
    conn.pragma_update(None, "user_version", 1)?;
    Ok(())
}
