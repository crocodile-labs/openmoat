//! A migration runs inside the first `openmoat guard` after an upgrade, within
//! its time budget, so a step must not copy the log: 0.14.0's version-8 step
//! rebuilt `events` and took minutes on a large log, during which every call
//! was denied.

use std::time::{Duration, Instant};

use rusqlite::Connection;

use super::*;

/// Rows in the version-7 log: enough that copying them shows (a rebuild of
/// this many took seconds), few enough to build quickly in a debug test.
const ROWS: i64 = 200_000;

/// A version-7 log as 0.13 wrote it, with `ROWS` events of a typical size.
const V7: &str = "
CREATE TABLE events (
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
CREATE INDEX events_session ON events(session_id, id);
CREATE INDEX events_ts ON events(ts_ms);
CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO meta (key, value) VALUES ('legacy_last_id', 0);
CREATE TABLE provenance (
    id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL, host TEXT NOT NULL,
    session_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tainted-write','clean-write','tainted-read')),
    path TEXT NOT NULL, sha256 TEXT, source TEXT NOT NULL);
CREATE TABLE session_writes (
    id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL, host TEXT NOT NULL,
    session_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT, before_sha256 TEXT,
    UNIQUE (host, session_id, path));
CREATE TABLE mcp_tickets (
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
PRAGMA user_version = 7;
";

const FILL: &str = "
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
INSERT INTO events (id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules,
                    reasons, latency_us)
SELECT i, 1700000000000 + i, 'claude-code', 'session-' || (i / 500), 'toolu_' || i,
       '/Users/me/projects/some-project', 'Bash',
       '{\"shell\":{\"command\":\"git status && cargo test -p openmoat --all-features | tail -40\"}}',
       'allow', '[\"dev-shell\"]', '[\"matched dev-shell: a common development command\"]', 1234
FROM n;
";

fn root_page(conn: &Connection, table: &str) -> i64 {
    conn.query_row(
        "SELECT rootpage FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )
    .unwrap()
}

fn version_7_log(path: &std::path::Path, schema: &str, rows: i64) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.execute_batch(schema).unwrap();
    conn.execute(FILL, [rows]).unwrap();
    conn
}

fn insert_review(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules, reasons,
                             latency_us)
         VALUES (0, 'h', 's', 't', 'null', 'review', '[]', '[]', 1)",
        [],
    )
}

#[test]
fn the_version_8_step_widens_in_place_and_copies_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    // A connection open before the upgrade, as a parallel `guard` would hold.
    let other = version_7_log(&path, V7, ROWS);
    let (events_root, tickets_root) = (
        root_page(&other, "events"),
        root_page(&other, "mcp_tickets"),
    );
    assert!(insert_review(&other).is_err(), "version 7 refuses `review`");

    let started = Instant::now();
    let store = Store::open_existing(&path).unwrap();
    let took = started.elapsed();

    // The tables were not rebuilt: a rebuild puts them on new pages.
    assert_eq!(root_page(&store.conn, "events"), events_root);
    assert_eq!(root_page(&store.conn, "mcp_tickets"), tickets_root);
    // Copying 200,000 rows took seconds; the widening takes milliseconds. The
    // bound leaves room for a slow CI machine.
    assert!(took < Duration::from_secs(2), "migration took {took:?}");
    assert_eq!(store.count().unwrap(), u64::try_from(ROWS).unwrap());

    // This handle, the connection opened before, and a new one all take the
    // new verdict, and the old `CHECK` still refuses a word it never knew.
    let mut decision = openmoat_core::Decision::new(openmoat_core::Verdict::Review);
    decision.rules.push("installs".to_owned());
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: None,
            tool: "Bash",
            action: None,
            decision: &decision,
            latency_us: 1,
        })
        .unwrap();
    insert_review(&other).unwrap();
    let fresh = Connection::open(&path).unwrap();
    insert_review(&fresh).unwrap();
    fresh
        .execute(
            "INSERT INTO mcp_tickets (event_id, ts_ms, host, session_id, tool, arguments_sha256,
                                      verdict)
             VALUES (1, 1, 'h', 's', 't', 'ab', 'review')",
            [],
        )
        .unwrap();
    let wrong = fresh.execute(
        "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules, reasons,
                             latency_us)
         VALUES (0, 'h', 's', 't', 'null', 'maybe', '[]', '[]', 1)",
        [],
    );
    assert!(
        wrong.is_err(),
        "the widened check still refuses other words"
    );
    let check: String = fresh
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(check, "ok");
    drop(store);
    assert_eq!(schema::version(&fresh).unwrap(), schema::SCHEMA_VERSION);
}

#[test]
fn a_check_written_differently_is_rebuilt_instead() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    // The same constraint, spaced otherwise: not the text the ladder wrote.
    let respaced = V7.replace(
        "CHECK (verdict IN ('allow','defer','ask','deny'))",
        "CHECK (verdict IN ( 'allow', 'defer', 'ask', 'deny' ))",
    );
    let conn = version_7_log(&path, &respaced, 1_000);
    let events_root = root_page(&conn, "events");
    drop(conn);

    let store = Store::open_existing(&path).unwrap();
    assert_ne!(root_page(&store.conn, "events"), events_root, "rebuilt");
    assert_eq!(store.count().unwrap(), 1_000);
    insert_review(&store.conn).unwrap();
}

#[test]
fn a_new_log_takes_every_verdict() {
    let store = Store::open_in_memory().unwrap();
    for verdict in ["allow", "defer", "review", "ask", "deny"] {
        store
            .conn
            .execute(
                "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules,
                                     reasons, latency_us)
                 VALUES (0, 'h', 's', 't', 'null', ?1, '[]', '[]', 1)",
                [verdict],
            )
            .unwrap();
    }
}
