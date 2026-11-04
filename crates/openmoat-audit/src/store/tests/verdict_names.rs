//! ADR-053: the verdict `ask` is now `review`. Rows written before keep `ask`,
//! because the chain hashes the stored text; every reader takes it as `review`.

use openmoat_core::{Action, Decision, Verdict};
use rusqlite::{Connection, params};

use super::*;
use crate::store::chain::Fields;

const OLD_ROW_ACTION: &str = r#"{"shell":{"command":"npm install left-pad"}}"#;

fn record(store: &Store, verdict: Verdict, command: &str) -> EventId {
    let mut decision = Decision::new(verdict);
    decision.rules.push("installs".to_owned());
    decision.reasons.push("package install".to_owned());
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: Some("/p"),
            tool: "Bash",
            action: Some(&action),
            decision: &decision,
            latency_us: 900,
        })
        .unwrap()
}

/// A version-7 database, as 0.13 left it, holding a hashed `ask` row after
/// `head`, the hash of the row before it.
fn put_back_version_7_with_an_ask_row(path: &std::path::Path, head: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "ALTER TABLE events RENAME TO events_new;
         CREATE TABLE events (
             id INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, host TEXT NOT NULL,
             session_id TEXT NOT NULL, call_id TEXT, cwd TEXT, tool TEXT NOT NULL,
             action TEXT NOT NULL,
             verdict TEXT NOT NULL CHECK (verdict IN ('allow','defer','ask','deny')),
             rules TEXT NOT NULL, reasons TEXT NOT NULL, latency_us INTEGER NOT NULL,
             prev_hash TEXT, hash TEXT);
         INSERT INTO events SELECT * FROM events_new;
         DROP TABLE events_new;
         DROP TABLE mcp_tickets;
         CREATE TABLE mcp_tickets (
             id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL,
             host TEXT NOT NULL, session_id TEXT NOT NULL, call_id TEXT,
             tool TEXT NOT NULL, arguments_sha256 TEXT NOT NULL,
             verdict TEXT NOT NULL CHECK (verdict IN ('allow','defer','ask')));
         INSERT INTO mcp_tickets (event_id, ts_ms, host, session_id, tool, arguments_sha256, verdict)
             VALUES (2, 1, 'claude-code', 's1', 'mcp__x__y', 'ab', 'ask');
         PRAGMA user_version = 7;",
    )
    .unwrap();
    let old = Fields {
        id: 2,
        ts_ms: 1_700_000_000_000,
        host: "claude-code",
        session_id: "s1",
        call_id: None,
        cwd: Some("/p"),
        tool: "Bash",
        action: OLD_ROW_ACTION,
        verdict: "ask",
        rules: r#"["installs"]"#,
        reasons: r#"["package install"]"#,
        latency_us: 900,
        prev_hash: head,
    };
    conn.execute(
        "INSERT INTO events (id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict,
                             rules, reasons, latency_us, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            old.id,
            old.ts_ms,
            old.host,
            old.session_id,
            old.call_id,
            old.cwd,
            old.tool,
            old.action,
            old.verdict,
            old.rules,
            old.reasons,
            old.latency_us,
            old.prev_hash,
            old.hash()
        ],
    )
    .unwrap();
    let refused = conn.execute(
        "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules, reasons, latency_us)
         VALUES (0, 'h', 's', 't', 'null', 'review', '[]', '[]', 1)",
        [],
    );
    assert!(refused.is_err(), "the version-7 check refuses `review`");
}

#[test]
fn an_old_ask_row_reads_as_review_and_the_chain_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head = {
        let store = Store::open(&path).unwrap();
        record(&store, Verdict::Allow, "git status");
        store.verify_chain().unwrap().head.unwrap()
    };
    put_back_version_7_with_an_ask_row(&path, &head);

    let store = Store::open(&path).unwrap();
    let report = store.verify_chain().unwrap();
    assert_eq!((report.events, report.broken), (2, None));
    assert_eq!(
        store.get(EventId(2)).unwrap().unwrap().verdict,
        Verdict::Review
    );

    // New rows record the new name, and the chain runs on across both.
    let id = record(&store, Verdict::Review, "npm install right-pad");
    let stored: String = store
        .conn
        .query_row("SELECT verdict FROM events WHERE id = ?1", [id.0], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(stored, "review");
    assert!(store.verify_chain().unwrap().broken.is_none());

    // An export carries each row's stored text, which its hash covers, and
    // reads both names as `review`.
    let lines = store.export(&ExportFilter::default()).unwrap();
    let verdicts: Vec<&str> = lines.iter().map(|l| l.verdict.as_str()).collect();
    assert_eq!(verdicts, ["allow", "ask", "review"]);
    for line in &lines[1..] {
        assert_eq!(line.to_event().unwrap().verdict, Verdict::Review);
    }
    let text: String = lines
        .iter()
        .map(|l| serde_json::to_string(l).unwrap() + "\n")
        .collect();
    let checked = verify_export(&text, None);
    assert_eq!((checked.events, checked.broken), (3, None));

    // The MCP decisions the hook kept keep their rows too.
    let tickets: i64 = store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM mcp_tickets WHERE verdict = 'ask'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tickets, 1);
}
