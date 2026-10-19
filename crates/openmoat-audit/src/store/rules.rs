//! Whether a session already recorded a rule, without decoding the session.

use rusqlite::params;

use super::{EventId, Store, StoreError};

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
}
