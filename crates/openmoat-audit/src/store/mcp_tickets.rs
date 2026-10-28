//! The MCP tool calls the hook let the host run, so `openmoat mcp proxy` can
//! tie each call it relays to the decision and the session behind it
//! (ADR-045).
//!
//! The hook adds one row for each MCP call it does not deny: the call's event,
//! session and tool name, and the SHA-256 of its arguments in canonical form.
//! The proxy takes the row that matches the call it is about to relay, which
//! removes it, so one decision lets one call through. Like the session writes
//! (`session_writes.rs`) the rows are a lookup, not a record: the events table
//! holds both the hook's decision and the proxy's. A row older than
//! [`MAX_AGE_MS`] matches nothing and is removed when a row is added or taken.

use rusqlite::{Transaction, TransactionBehavior, params};

use super::{EventId, Store, StoreError, now_ms};

/// A decision lets its call through for this long: a person may take a while
/// to answer the host's question, and the host sends the call after.
pub const MAX_AGE_MS: i64 = 60 * 60 * 1000;

/// A row the hook adds. Its texts are redacted as an event's are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTicket<'a> {
    /// The event of the hook's decision.
    pub event: EventId,
    /// The host's id.
    pub host: &'a str,
    /// The session that made the call.
    pub session_id: &'a str,
    /// The host's id for the call, when it sent one.
    pub call_id: Option<&'a str>,
    /// The MCP tool name the hook decided (`mcp__<server>__<tool>`, or the
    /// host's own spelling).
    pub tool: &'a str,
    /// Lowercase hex SHA-256 of the call's arguments in canonical form.
    pub arguments_sha256: &'a str,
    /// The hook's verdict (`allow`, `defer` or `ask`).
    pub verdict: &'a str,
}

/// A row the proxy took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// The event of the hook's decision.
    pub event_id: EventId,
    /// When the hook decided (ms since the epoch).
    pub ts_ms: i64,
    /// The host's id.
    pub host: String,
    /// The session that made the call.
    pub session_id: String,
    /// The host's id for the call.
    pub call_id: Option<String>,
    /// The MCP tool name the hook decided.
    pub tool: String,
    /// The hook's verdict.
    pub verdict: String,
}

impl Store {
    /// Add the hook's row for one MCP call and remove rows past their age.
    pub fn add_mcp_ticket(&self, ticket: &NewTicket<'_>) -> Result<(), StoreError> {
        if !self.mcp_tickets() {
            return Ok(());
        }
        let secrets = &self.secrets;
        let ts_ms = now_ms();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM mcp_tickets WHERE ts_ms < ?1",
            params![ts_ms.saturating_sub(MAX_AGE_MS)],
        )?;
        tx.execute(
            "INSERT INTO mcp_tickets (event_id, ts_ms, host, session_id, call_id, tool,
                                      arguments_sha256, verdict)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ticket.event.0,
                ts_ms,
                secrets.redact(ticket.host),
                secrets.redact(ticket.session_id),
                ticket.call_id.map(|c| secrets.redact(c)),
                secrets.redact(ticket.tool),
                ticket.arguments_sha256,
                ticket.verdict,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Take the oldest row younger than [`MAX_AGE_MS`] for arguments with
    /// `arguments_sha256` that `matches` accepts (the tool the proxy relays),
    /// removing it, in one transaction: two proxies never take the same row.
    /// `None` when no row matches.
    pub fn take_mcp_ticket(
        &self,
        arguments_sha256: &str,
        matches: impl Fn(&Ticket) -> bool,
    ) -> Result<Option<Ticket>, StoreError> {
        if !self.mcp_tickets() {
            return Ok(None);
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM mcp_tickets WHERE ts_ms < ?1",
            params![now_ms().saturating_sub(MAX_AGE_MS)],
        )?;
        let candidates: Vec<(i64, Ticket)> = {
            let mut statement = tx.prepare_cached(
                "SELECT id, event_id, ts_ms, host, session_id, call_id, tool, verdict
                 FROM mcp_tickets WHERE arguments_sha256 = ?1 ORDER BY id",
            )?;
            let rows = statement.query_map(params![arguments_sha256], |row| {
                Ok((
                    row.get(0)?,
                    Ticket {
                        event_id: EventId(row.get(1)?),
                        ts_ms: row.get(2)?,
                        host: row.get(3)?,
                        session_id: row.get(4)?,
                        call_id: row.get(5)?,
                        tool: row.get(6)?,
                        verdict: row.get(7)?,
                    },
                ))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let taken = candidates.into_iter().find(|(_, ticket)| matches(ticket));
        if let Some((id, _)) = &taken {
            tx.execute("DELETE FROM mcp_tickets WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(taken.map(|(_, ticket)| ticket))
    }
}
