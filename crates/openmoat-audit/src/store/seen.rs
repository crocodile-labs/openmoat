//! When a host's hook last reached the guard, for `openmoat status` and
//! `openmoat doctor` to tell a plugin that loaded from one that did not.

use rusqlite::{OptionalExtension as _, params};

use super::{Store, StoreError};

impl Store {
    /// The time of the newest event `host` recorded at or after `since_ms`,
    /// or `None` when it recorded none. `host` is matched as [`Store::record`]
    /// stored it, redacted. Reads only the events from `since_ms` on, by the
    /// time index.
    pub fn host_seen_since(&self, host: &str, since_ms: i64) -> Result<Option<i64>, StoreError> {
        let host = self.secrets.redact(host);
        Ok(self
            .conn
            .query_row(
                "SELECT ts_ms FROM events WHERE ts_ms >= ?1 AND host = ?2 \
                 ORDER BY ts_ms DESC LIMIT 1",
                params![since_ms, host],
                |row| row.get(0),
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Decision, Verdict};

    use crate::{NewEvent, Store};

    #[test]
    fn the_newest_event_of_the_host_since_a_time() {
        let store = Store::open_in_memory().unwrap();
        let decision = Decision::new(Verdict::Allow);
        let event = |host| NewEvent {
            host,
            session_id: "s",
            call_id: None,
            cwd: None,
            tool: "bash",
            action: None,
            decision: &decision,
            latency_us: 1,
        };
        store.record_at(&event("pi"), 100).unwrap();
        store.record_at(&event("pi"), 200).unwrap();
        store.record_at(&event("codex"), 300).unwrap();
        assert_eq!(store.host_seen_since("pi", 0).unwrap(), Some(200));
        assert_eq!(store.host_seen_since("pi", 200).unwrap(), Some(200));
        assert_eq!(store.host_seen_since("pi", 201).unwrap(), None);
        assert_eq!(store.host_seen_since("openclaw", 0).unwrap(), None);
    }
}
