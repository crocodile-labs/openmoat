//! The event query for each schema version, read by [`super::row_to_event`]:
//! a column the database does not have yet is selected as `NULL`, so every
//! row decodes the same way.

use super::Store;

const SELECT_PHASES: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, prev_hash, hash, phases_us FROM events";
const SELECT_CHAINED: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, prev_hash, hash, NULL FROM events";
const SELECT_UNCHAINED: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us, NULL, NULL, NULL FROM events";

impl Store {
    /// The event query for this database's schema, for [`super::row_to_event`].
    pub(crate) fn select(&self) -> &'static str {
        if self.phases() {
            SELECT_PHASES
        } else if self.chained() {
            SELECT_CHAINED
        } else {
            SELECT_UNCHAINED
        }
    }
}
