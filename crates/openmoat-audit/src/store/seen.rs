//! When a host's hook last reached the guard, for `openmoat status` and
//! `openmoat doctor` to tell a plugin that loaded from one that did not.

use rusqlite::{OptionalExtension as _, params};

use super::{Store, StoreError};

impl Store {
    /// The time of the newest event `host` recorded at or after `since_ms`,
    /// or `None` when it recorded none. `host` is matched as [`Store::record`]
    /// stored it, redacted. Reads only the events from `since_ms` on, by the
    /// time index. An event a package from the agent's own plugin channel
    /// decided ([`Store::from_package`]) is left out: it shows the package
    /// ran, not that `openmoat init`'s hook or plugin did.
    pub fn host_seen_since(&self, host: &str, since_ms: i64) -> Result<Option<i64>, StoreError> {
        let host = self.secrets.redact(host);
        let query = if self.package_events() {
            "SELECT ts_ms FROM events WHERE ts_ms >= ?1 AND host = ?2 \
             AND id NOT IN (SELECT event_id FROM package_events) \
             ORDER BY ts_ms DESC LIMIT 1"
        } else {
            "SELECT ts_ms FROM events WHERE ts_ms >= ?1 AND host = ?2 \
             ORDER BY ts_ms DESC LIMIT 1"
        };
        Ok(self
            .conn
            .query_row(query, params![since_ms, host], |row| row.get(0))
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Decision, Verdict};
    use rusqlite::Connection;

    use crate::{NewEvent, Store};

    fn event<'a>(host: &'a str, decision: &'a Decision) -> NewEvent<'a> {
        NewEvent {
            host,
            session_id: "s",
            call_id: None,
            cwd: None,
            tool: "bash",
            action: None,
            decision,
            latency_us: 1,
        }
    }

    #[test]
    fn the_newest_event_of_the_host_since_a_time() {
        let store = Store::open_in_memory().unwrap();
        let decision = Decision::new(Verdict::Allow);
        store.record_at(&event("host-a", &decision), 100).unwrap();
        store.record_at(&event("host-a", &decision), 200).unwrap();
        store.record_at(&event("host-b", &decision), 300).unwrap();
        assert_eq!(store.host_seen_since("host-a", 0).unwrap(), Some(200));
        assert_eq!(store.host_seen_since("host-a", 200).unwrap(), Some(200));
        assert_eq!(store.host_seen_since("host-a", 201).unwrap(), None);
        assert_eq!(store.host_seen_since("host-c", 0).unwrap(), None);
    }

    /// A call a package decided is in the log and its chain, but is no sign
    /// that `init`'s plugin loaded.
    #[test]
    fn a_package_s_events_are_kept_but_not_counted_as_seen() {
        let store = Store::open_in_memory().unwrap();
        let decision = Decision::new(Verdict::Deny);
        store.record_at(&event("host-a", &decision), 100).unwrap();
        let store = store.from_package(true);
        store.record_at(&event("host-a", &decision), 200).unwrap();
        assert_eq!(store.host_seen_since("host-a", 0).unwrap(), Some(100));
        assert_eq!(store.host_seen_since("host-a", 101).unwrap(), None);
        let store = store.from_package(false);
        store.record_at(&event("host-a", &decision), 300).unwrap();
        assert_eq!(store.host_seen_since("host-a", 0).unwrap(), Some(300));
        assert_eq!(store.recent(10).unwrap().len(), 3);
        let chain = store.verify_chain().unwrap();
        assert!(chain.broken.is_none(), "the chain holds: {chain:?}");
    }

    /// A database the previous version wrote gains the table on open, and its
    /// events still count.
    #[test]
    fn a_version_10_database_opens_and_its_events_count() {
        let dir = std::env::temp_dir().join(format!("openmoat-seen-v10-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.db");
        {
            let store = Store::open(&path)
                .unwrap()
                .with_chain_key(crate::ChainKey::new([9; 32], crate::EventId(0)));
            let decision = Decision::new(Verdict::Allow);
            store.record_at(&event("host-a", &decision), 100).unwrap();
        }
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("DROP TABLE package_events;").unwrap();
            conn.pragma_update(None, "user_version", 10).unwrap();
        }
        let read = Store::open_read_only(&path).unwrap();
        assert_eq!(read.host_seen_since("host-a", 0).unwrap(), Some(100));
        drop(read);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.host_seen_since("host-a", 0).unwrap(), Some(100));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
