//! How long each step of `openmoat guard` took on the call an event records
//! (ADR-130), beside the call's `latency_us`: the column `phases_us` of
//! version 13. Durations only: a step's name, which the guard takes from its
//! own fixed list, and microseconds, never anything of the payload.
//!
//! The column is outside the hash chain and the audit key's MAC: the figures
//! are for finding a slow step, not evidence of what was decided, and keeping
//! them out leaves every chain and export as it was. A row from before
//! version 13, or one another writer recorded, has none.

use super::{Store, schema};

/// The longest step name kept; a longer one, or one with anything but
/// lowercase ASCII letters, is left out.
const MAX_NAME: usize = 16;

/// The step names and microseconds of one call, in the order given.
pub type PhaseTimes = Vec<(String, u64)>;

impl Store {
    /// This handle, recording `times` (a step's name and the microseconds the
    /// call spent in it) with every event it records from now on. A name
    /// must be lowercase ASCII letters, at most 16 of them; any other entry
    /// is dropped, so nothing but a step's name can reach the column.
    #[must_use]
    pub fn with_phase_times(self, times: &[(&'static str, u64)]) -> Self {
        let kept: Vec<(&'static str, u64)> = times
            .iter()
            .copied()
            .filter(|(name, _)| is_step_name(name))
            .collect();
        Self {
            phase_times: (!kept.is_empty()).then_some(kept),
            ..self
        }
    }

    /// The schema has the `phases_us` column (version 13).
    pub(super) fn phases(&self) -> bool {
        self.version >= schema::PHASES_VERSION
    }

    /// The `phases_us` cell this handle writes with an event.
    pub(super) fn phases_cell(&self) -> Option<String> {
        self.phase_times
            .as_ref()
            .and_then(|times| serde_json::to_string(times).ok())
    }
}

fn is_step_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(|b| b.is_ascii_lowercase())
}

/// The times a `phases_us` cell holds; `None` for none, or for a cell that
/// cannot be read (they are figures, so a bad cell does not fail the query).
pub(super) fn decode(cell: Option<&str>) -> Option<PhaseTimes> {
    let times: PhaseTimes = serde_json::from_str(cell?).ok()?;
    let readable = times.iter().all(|(name, _)| is_step_name(name));
    (readable && !times.is_empty()).then_some(times)
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Decision, Verdict};

    use super::*;
    use crate::NewEvent;

    fn record(store: &Store) -> crate::EventId {
        let decision = Decision::new(Verdict::Allow);
        store
            .record(&NewEvent {
                host: "h",
                session_id: "s",
                call_id: None,
                cwd: None,
                tool: "Bash",
                action: None,
                decision: &decision,
                latency_us: 900,
            })
            .unwrap()
    }

    #[test]
    fn the_times_are_recorded_with_the_event_and_read_back() {
        let store = Store::open_in_memory().unwrap().with_phase_times(&[
            ("stdin", 12),
            ("lock", 340),
            ("record", 500),
        ]);
        let event = store.get(record(&store)).unwrap().unwrap();
        let times = event.phases_us.unwrap();
        assert_eq!(
            times,
            [
                ("stdin".to_owned(), 12),
                ("lock".to_owned(), 340),
                ("record".to_owned(), 500)
            ]
        );
        assert!(store.verify_chain().unwrap().broken.is_none());
    }

    #[test]
    fn a_handle_without_times_records_none() {
        let store = Store::open_in_memory().unwrap();
        let event = store.get(record(&store)).unwrap().unwrap();
        assert_eq!(event.phases_us, None);
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("phases_us").is_none(), "{json}");
    }

    #[test]
    fn only_step_names_reach_the_column() {
        let store = Store::open_in_memory().unwrap().with_phase_times(&[
            ("lock", 1),
            ("Lock", 2),
            ("has space", 3),
            ("", 4),
            ("averyveryverylongname", 5),
        ]);
        let event = store.get(record(&store)).unwrap().unwrap();
        assert_eq!(event.phases_us.unwrap(), [("lock".to_owned(), 1)]);
        let none = Store::open_in_memory()
            .unwrap()
            .with_phase_times(&[("Bad", 1)]);
        assert_eq!(none.phases_cell(), None);
    }

    /// A log an older build wrote has no `phases_us`: read as it is, and after
    /// the upgrade adds the column, its rows have none, and new rows have them.
    #[test]
    fn rows_from_before_version_13_have_no_times() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            schema::create_at(&conn, 11).unwrap();
            conn.execute(
                "INSERT INTO events (ts_ms, host, session_id, tool, action, verdict, rules,
                                     reasons, latency_us)
                 VALUES (1, 'h', 's', 'Bash', 'null', 'allow', '[]', '[]', 5)",
                [],
            )
            .unwrap();
        }
        let old = Store::open_read_only(&path).unwrap();
        assert!(!old.phases());
        let events = old.session("s").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].phases_us, None);
        drop(old);
        let store = Store::open(&path).unwrap();
        assert!(store.phases());
        assert!(schema::has_column(&store.conn, "events", "phases_us").unwrap());
        assert_eq!(store.session("s").unwrap()[0].phases_us, None);
        // The key starts after the old row, as `audit_key.rs` makes it.
        let (after, hash) = store.key_start().unwrap();
        let key = crate::ChainKey::new(&[7; 32], after, hash.as_deref());
        let store = store.with_chain_key(key).with_phase_times(&[("lock", 3)]);
        let decision = Decision::new(Verdict::Allow);
        let event = NewEvent {
            host: "h",
            session_id: "s",
            call_id: None,
            cwd: None,
            tool: "Bash",
            action: None,
            decision: &decision,
            latency_us: 9,
        };
        store.record(&event).unwrap();
        let rows = store.session("s").unwrap();
        assert_eq!(rows[0].phases_us, None);
        assert_eq!(rows[1].phases_us, Some(vec![("lock".to_owned(), 3)]));
    }

    #[test]
    fn an_unreadable_cell_reads_as_none() {
        assert_eq!(decode(None), None);
        assert_eq!(decode(Some("not json")), None);
        assert_eq!(decode(Some("[]")), None);
        assert_eq!(decode(Some(r#"[["sec ret",1]]"#)), None);
        assert_eq!(
            decode(Some(r#"[["lock",7]]"#)),
            Some(vec![("lock".to_owned(), 7)])
        );
    }
}
