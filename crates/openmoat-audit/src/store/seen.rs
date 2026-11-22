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

    /// Each session of `host` whose start, an event of tool `start_tool`,
    /// was recorded at or after `since_ms`: when it started and how many other
    /// events (its calls) the session recorded, for the faster liveness check
    /// (ADR-109). `host` and the session ids are matched as [`Store::record`]
    /// stored them, redacted.
    pub fn sessions_started_since(
        &self,
        host: &str,
        start_tool: &str,
        since_ms: i64,
    ) -> Result<Vec<StartedSession>, StoreError> {
        let host = self.secrets.redact(host);
        let mut stmt = self.conn.prepare(
            "SELECT session_id, MIN(CASE WHEN tool = ?3 THEN ts_ms END), \
             SUM(CASE WHEN tool = ?3 THEN 0 ELSE 1 END) FROM events \
             WHERE host = ?2 AND session_id IN \
             (SELECT session_id FROM events WHERE ts_ms >= ?1 AND host = ?2 AND tool = ?3) \
             GROUP BY session_id ORDER BY 2",
        )?;
        let rows = stmt.query_map(params![since_ms, host, start_tool], |row| {
            Ok(StartedSession {
                session_id: row.get(0)?,
                started_ms: row.get(1)?,
                calls: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// A session whose start reached the guard ([`Store::sessions_started_since`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedSession {
    /// The session's id, as recorded.
    pub session_id: String,
    /// When its first start was recorded.
    pub started_ms: i64,
    /// How many of its events are not starts: the calls that reached the guard.
    pub calls: i64,
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Decision, Verdict};
    use rusqlite::Connection;

    use super::StartedSession;
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

    #[test]
    fn a_started_session_counts_its_calls() {
        let store = Store::open_in_memory().unwrap();
        let decision = Decision::new(Verdict::Allow);
        let at = |session: &'static str, tool: &'static str| NewEvent {
            session_id: session,
            tool,
            ..event("host-a", &decision)
        };
        store.record_at(&at("one", "SessionStart"), 100).unwrap();
        store.record_at(&at("two", "SessionStart"), 150).unwrap();
        store.record_at(&at("two", "Bash"), 160).unwrap();
        store.record_at(&at("old", "Bash"), 10).unwrap();
        let started = store
            .sessions_started_since("host-a", "SessionStart", 50)
            .unwrap();
        assert_eq!(
            started,
            vec![
                StartedSession {
                    session_id: "one".into(),
                    started_ms: 100,
                    calls: 0
                },
                StartedSession {
                    session_id: "two".into(),
                    started_ms: 150,
                    calls: 1
                },
            ]
        );
        assert_eq!(
            store
                .sessions_started_since("host-b", "SessionStart", 0)
                .unwrap(),
            Vec::new()
        );
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
                .with_chain_key(crate::ChainKey::new(&[9; 32], crate::EventId(0), None));
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
