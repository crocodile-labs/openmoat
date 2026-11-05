//! What each MCP server's tool results held, per session, so the hook can
//! tell when a call carries one server's text to another (ADR-058).
//!
//! `openmoat mcp proxy` adds a row for each piece of a result it relays (an
//! address, a long token, a run of words; `openmoat_core::mcp_flow::pieces`)
//! under the session the hook's decision for the call named (ADR-045). A row
//! holds a hash of the piece, never its text. The hook looks up the pieces of
//! an MCP call's arguments and learns which servers returned them. Like the
//! MCP tickets (`mcp_tickets.rs`) the rows are a lookup, not a record: they
//! are removed after [`MAX_AGE_MS`], and a session keeps its newest
//! [`MAX_SESSION_ROWS`].

use rusqlite::{Transaction, TransactionBehavior, params};

use super::{Store, StoreError, now_ms};

/// A piece is remembered for this long: a session's work rarely spans more,
/// and an older result is less likely to steer the call being decided.
pub const MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// The most rows one session keeps; the oldest go first.
pub const MAX_SESSION_ROWS: i64 = 16_384;

/// The most pieces one lookup reads; a call's arguments give at most
/// `openmoat_core::mcp_flow::MAX_PIECES`.
const MAX_LOOKUP: usize = 1024;

impl Store {
    /// Remember that MCP server `server` returned the pieces with
    /// `piece_hashes` to `session_id` of `host`. A piece seen again moves to
    /// now. Rows past their age and a session's rows past its limit are removed.
    pub fn add_mcp_flow(
        &self,
        host: &str,
        session_id: &str,
        server: &str,
        piece_hashes: &[String],
    ) -> Result<(), StoreError> {
        if !self.mcp_flow() || piece_hashes.is_empty() {
            return Ok(());
        }
        let secrets = &self.secrets;
        let (host, session_id, server) = (
            secrets.redact(host),
            secrets.redact(session_id),
            secrets.redact(server),
        );
        let ts_ms = now_ms();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM mcp_flow WHERE ts_ms < ?1",
            params![ts_ms.saturating_sub(MAX_AGE_MS)],
        )?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO mcp_flow (ts_ms, host, session_id, server, piece)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (host, session_id, server, piece) DO UPDATE SET ts_ms = excluded.ts_ms",
            )?;
            for piece in piece_hashes {
                insert.execute(params![ts_ms, host, session_id, server, piece])?;
            }
        }
        tx.execute(
            "DELETE FROM mcp_flow WHERE host = ?1 AND session_id = ?2 AND id NOT IN (
                 SELECT id FROM mcp_flow WHERE host = ?1 AND session_id = ?2
                 ORDER BY ts_ms DESC, id DESC LIMIT ?3)",
            params![host, session_id, MAX_SESSION_ROWS],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The MCP servers that returned any of the pieces with `piece_hashes` to
    /// `session_id` of `host` within [`MAX_AGE_MS`], sorted and each once.
    /// Empty on a database older than the table.
    pub fn mcp_flow_sources(
        &self,
        host: &str,
        session_id: &str,
        piece_hashes: &[String],
    ) -> Result<Vec<String>, StoreError> {
        if !self.mcp_flow() || piece_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let secrets = &self.secrets;
        let (host, session_id) = (secrets.redact(host), secrets.redact(session_id));
        let since = now_ms().saturating_sub(MAX_AGE_MS);
        let mut statement = self.conn.prepare_cached(
            "SELECT DISTINCT server FROM mcp_flow
             WHERE host = ?1 AND session_id = ?2 AND piece = ?3 AND ts_ms >= ?4",
        )?;
        let mut servers = std::collections::BTreeSet::new();
        for piece in piece_hashes.iter().take(MAX_LOOKUP) {
            let rows = statement.query_map(params![host, session_id, piece, since], |row| {
                row.get::<_, String>(0)
            })?;
            for server in rows {
                servers.insert(server?);
            }
        }
        Ok(servers.into_iter().collect())
    }
}
