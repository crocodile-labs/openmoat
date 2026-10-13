//! Time-window queries and aggregates over the audit log, used by
//! `moat replay` and `moat report`.

use std::collections::BTreeMap;

use openmoat_core::Verdict;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::store::{Event, Store, StoreError, row_to_event};

const MS_PER_HOUR: i64 = 3_600_000;
const TOP_RULES: usize = 10;

/// One host session as seen in a time window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session id as the host reported it.
    pub session_id: String,
    /// Host id (`claude-code`, `codex`, `cursor`).
    pub host: String,
    /// Working directory of the first event, if recorded.
    pub cwd: Option<String>,
    /// Time of the first event (ms since the epoch).
    pub first_ms: i64,
    /// Time of the last event (ms since the epoch).
    pub last_ms: i64,
    /// The session's events, oldest first.
    pub events: Vec<Event>,
}

impl SessionSummary {
    /// Number of events with `verdict`.
    #[must_use]
    pub fn count(&self, verdict: Verdict) -> usize {
        self.events.iter().filter(|e| e.verdict == verdict).count()
    }
}

/// Aggregate view of a time window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Start of the window (ms since the epoch).
    pub since_ms: i64,
    /// Events in the window.
    pub total: u64,
    /// Events that were allowed.
    pub allowed: u64,
    /// Events left to the agent's own permission prompt (ADR-025).
    #[serde(default)]
    pub deferred: u64,
    /// Events that asked.
    pub asked: u64,
    /// Events that were denied.
    pub denied: u64,
    /// Distinct sessions in the window.
    pub sessions: u64,
    /// Events per host id.
    pub by_host: BTreeMap<String, u64>,
    /// Rule id → times it decided an `ask` or `deny`, most frequent first.
    pub top_rules: Vec<(String, u64)>,
    /// Distinct clock hours with at least one event.
    pub active_hours: u64,
}

impl Summary {
    /// Prompts per hour of agent activity, in hundredths; the prompt-fatigue
    /// metric `moat report` shows (`250` means 2.50 asks per active hour).
    #[must_use]
    pub fn asks_per_active_hour_centi(&self) -> u64 {
        if self.active_hours == 0 {
            return 0;
        }
        self.asked * 100 / self.active_hours
    }
}

impl Store {
    /// Events at or after `since_ms`, optionally for one host, oldest first.
    pub fn since(&self, since_ms: i64, host: Option<&str>) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE ts_ms >= ?1 AND (?2 IS NULL OR host = ?2) ORDER BY id",
            self.select()
        ))?;
        let rows = stmt.query_map(params![since_ms, host], row_to_event)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Events since `since_ms` grouped into sessions, oldest session first.
    pub fn sessions_since(
        &self,
        since_ms: i64,
        host: Option<&str>,
    ) -> Result<Vec<SessionSummary>, StoreError> {
        let mut sessions: Vec<SessionSummary> = Vec::new();
        for event in self.since(since_ms, host)? {
            match sessions
                .iter_mut()
                .find(|s| s.session_id == event.session_id && s.host == event.host)
            {
                Some(session) => {
                    session.last_ms = event.ts_ms;
                    if session.cwd.is_none() {
                        session.cwd.clone_from(&event.cwd);
                    }
                    session.events.push(event);
                }
                None => sessions.push(SessionSummary {
                    session_id: event.session_id.clone(),
                    host: event.host.clone(),
                    cwd: event.cwd.clone(),
                    first_ms: event.ts_ms,
                    last_ms: event.ts_ms,
                    events: vec![event],
                }),
            }
        }
        Ok(sessions)
    }

    /// Aggregate the window; see [`Summary::of`].
    pub fn summary(&self, since_ms: i64, host: Option<&str>) -> Result<Summary, StoreError> {
        Ok(Summary::of(since_ms, &self.since(since_ms, host)?))
    }
}

impl Summary {
    /// Aggregate `events` for a window starting at `since_ms`. Rules are counted
    /// only for `ask` and `deny` outcomes, which is what a policy author wants to tune.
    #[must_use]
    pub fn of(since_ms: i64, events: &[Event]) -> Self {
        let mut summary = Self {
            since_ms,
            total: 0,
            allowed: 0,
            deferred: 0,
            asked: 0,
            denied: 0,
            sessions: 0,
            by_host: BTreeMap::new(),
            top_rules: Vec::new(),
            active_hours: 0,
        };
        let mut rules: BTreeMap<String, u64> = BTreeMap::new();
        let mut sessions: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        let mut hours: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
        for event in events {
            summary.total += 1;
            match event.verdict {
                Verdict::Allow => summary.allowed += 1,
                Verdict::Defer => summary.deferred += 1,
                Verdict::Ask => summary.asked += 1,
                // `Deny`, and any verdict added to the core later.
                _ => summary.denied += 1,
            }
            *summary.by_host.entry(event.host.clone()).or_insert(0) += 1;
            sessions.insert((event.host.clone(), event.session_id.clone()));
            hours.insert(event.ts_ms.div_euclid(MS_PER_HOUR));
            if matches!(event.verdict, Verdict::Ask | Verdict::Deny) {
                for rule in &event.rules {
                    *rules.entry(rule.clone()).or_insert(0) += 1;
                }
            }
        }
        summary.sessions = sessions.len() as u64;
        summary.active_hours = hours.len() as u64;
        let mut top: Vec<(String, u64)> = rules.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(TOP_RULES);
        summary.top_rules = top;
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewEvent;
    use openmoat_core::{Action, Decision};

    fn decision(verdict: Verdict, rules: &[&str]) -> Decision {
        let mut d = Decision::new(verdict);
        d.rules = rules.iter().map(|r| (*r).to_owned()).collect();
        d.reasons = rules.iter().map(|r| format!("because {r}")).collect();
        d
    }

    fn seed(store: &Store) {
        let allow = decision(Verdict::Allow, &["dev-shell"]);
        let ask = decision(Verdict::Ask, &["installs"]);
        let deny = decision(Verdict::Deny, &["secrets-paths", "default.net"]);
        let action = Action::Shell {
            command: "x".into(),
        };
        let rows: [(&str, &str, &Decision, i64); 6] = [
            ("claude-code", "s1", &allow, 1_000),
            ("claude-code", "s1", &deny, 2_000),
            ("claude-code", "s2", &ask, MS_PER_HOUR + 1_000),
            ("cursor", "c1", &deny, MS_PER_HOUR + 2_000),
            ("cursor", "c1", &allow, 2 * MS_PER_HOUR),
            ("codex", "k1", &ask, 3 * MS_PER_HOUR),
        ];
        for (host, session, d, ts) in rows {
            store
                .record_at(
                    &NewEvent {
                        host,
                        session_id: session,
                        call_id: None,
                        cwd: Some("/p"),
                        tool: "Bash",
                        action: Some(&action),
                        decision: d,
                        latency_us: 1,
                    },
                    ts,
                )
                .unwrap();
        }
    }

    #[test]
    fn since_filters_by_time_and_host() {
        let store = Store::open_in_memory().unwrap();
        seed(&store);
        assert_eq!(store.since(0, None).unwrap().len(), 6);
        assert_eq!(store.since(MS_PER_HOUR, None).unwrap().len(), 4);
        assert_eq!(store.since(0, Some("cursor")).unwrap().len(), 2);
        let first = &store.since(0, None).unwrap()[0];
        assert_eq!(first.ts_ms, 1_000, "oldest first");
    }

    #[test]
    fn sessions_group_in_order_with_bounds() {
        let store = Store::open_in_memory().unwrap();
        seed(&store);
        let sessions = store.sessions_since(0, None).unwrap();
        let ids: Vec<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert_eq!(ids, ["s1", "s2", "c1", "k1"]);
        let s1 = &sessions[0];
        assert_eq!((s1.first_ms, s1.last_ms), (1_000, 2_000));
        assert_eq!(s1.count(Verdict::Deny), 1);
        assert_eq!(s1.cwd.as_deref(), Some("/p"));
    }

    #[test]
    fn summary_counts_verdicts_hosts_rules_and_hours() {
        let store = Store::open_in_memory().unwrap();
        seed(&store);
        let s = store.summary(0, None).unwrap();
        assert_eq!((s.total, s.allowed, s.asked, s.denied), (6, 2, 2, 2));
        assert_eq!(s.sessions, 4);
        assert_eq!(s.by_host["claude-code"], 3);
        assert_eq!(s.top_rules[0], ("default.net".to_owned(), 2));
        assert!(
            s.top_rules.iter().all(|(r, _)| r != "dev-shell"),
            "allow rules are not counted"
        );
        assert_eq!(s.active_hours, 4);
        assert_eq!(s.asks_per_active_hour_centi(), 50);
        let cursor = store.summary(0, Some("cursor")).unwrap();
        assert_eq!(cursor.total, 2);
        assert_eq!(cursor.by_host.len(), 1);
        let empty = Store::open_in_memory().unwrap().summary(0, None).unwrap();
        assert_eq!(empty.asks_per_active_hour_centi(), 0);
    }
}
