//! Whether a session already recorded a rule, without decoding the session.

use rusqlite::params;

use super::{Event, EventId, Store, StoreError};

impl Store {
    /// Whether an event of `session_id` lists `rule` among its rules.
    /// `session_id` is matched as [`Store::record`] stored it, redacted.
    ///
    /// `LIKE` on the rules cell only narrows the rows: each one it keeps is
    /// decoded and checked for `rule` exactly, and the scan stops at the first
    /// that has it. A kept row whose rules do not decode is an error.
    pub fn session_has_rule(&self, session_id: &str, rule: &str) -> Result<bool, StoreError> {
        let session_id = self.secrets.redact(session_id);
        let pattern = format!("%{}%", serde_json::to_string(rule)?);
        let mut stmt = self.conn.prepare(
            "SELECT id, rules FROM events WHERE session_id = ?1 AND rules LIKE ?2 ORDER BY id",
        )?;
        let mut rows = stmt.query(params![session_id, pattern])?;
        while let Some(row) = rows.next()? {
            let id = EventId(row.get(0)?);
            let text: String = row.get(1)?;
            let rules: Vec<String> =
                serde_json::from_str(&text).map_err(|e| StoreError::Decode {
                    id,
                    reason: format!("rules: {e}"),
                })?;
            if rules.iter().any(|r| r == rule) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The events recorded at or after `since_ms` that list `rule` among their
    /// rules: how many, in how many sessions, and the newest of them; `None`
    /// when there are none. Matched as [`Store::session_has_rule`] matches,
    /// `LIKE` to narrow and each kept row checked exactly.
    pub fn rule_since(&self, rule: &str, since_ms: i64) -> Result<Option<RuleSeen>, StoreError> {
        let pattern = format!("%{}%", serde_json::to_string(rule)?);
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, rules FROM events WHERE ts_ms >= ?1 AND rules LIKE ?2 \
             ORDER BY id",
        )?;
        let mut rows = stmt.query(params![since_ms, pattern])?;
        let mut count = 0;
        let mut sessions = std::collections::HashSet::new();
        let mut newest = None;
        while let Some(row) = rows.next()? {
            let id = EventId(row.get(0)?);
            let session: String = row.get(1)?;
            let text: String = row.get(2)?;
            let rules: Vec<String> =
                serde_json::from_str(&text).map_err(|e| StoreError::Decode {
                    id,
                    reason: format!("rules: {e}"),
                })?;
            if rules.iter().any(|r| r == rule) {
                count += 1;
                sessions.insert(session);
                newest = Some(id);
            }
        }
        let Some(newest) = newest else {
            return Ok(None);
        };
        let Some(newest) = self.get(newest)? else {
            return Ok(None);
        };
        Ok(Some(RuleSeen {
            count,
            sessions: sessions.len(),
            newest,
        }))
    }
}

/// The recent events that list one rule ([`Store::rule_since`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSeen {
    /// How many there are.
    pub count: usize,
    /// In how many sessions.
    pub sessions: usize,
    /// The newest of them.
    pub newest: Event,
}
