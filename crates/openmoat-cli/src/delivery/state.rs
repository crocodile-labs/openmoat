//! Each sink's progress (`~/.moat/delivery/<sink>.json`): the last event it
//! accepted, the failures since, when to try again, and the gaps it has yet
//! to be told about. The audit log itself is the queue (ADR-081): this file
//! holds a position in it, never a copy of an event.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use openmoat_audit::EventId;
use openmoat_audit::delivery::Gap;
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};

/// The first wait after a failure; it doubles with each failure after.
const FIRST_WAIT: Duration = Duration::from_secs(5);
/// The longest wait between two tries.
pub const MAX_WAIT: Duration = Duration::from_mins(15);
/// The longest `Retry-After` honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_hours(1);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The newest event the sink accepted, or the one before where it
    /// started; `None` before its first run. `0` is before the first event,
    /// which [`EventId`]'s own reading refuses (no event has that id), so
    /// the file writes and reads it through [`cursor`].
    #[serde(default, with = "cursor")]
    pub cursor: Option<EventId>,
    /// Failed tries since the last accepted request.
    #[serde(default)]
    pub failures: u32,
    /// Not before this time (ms) unless a person runs `flush`.
    #[serde(default)]
    pub next_attempt_ms: i64,
    /// Why the sink stopped: an answer that trying again cannot change (a
    /// `401`, a `404`). Only a person's `openmoat audit deliver flush`
    /// resumes it.
    #[serde(default)]
    pub paused: Option<String>,
    /// The last failure, kept after a success for `status`.
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_error_ms: Option<i64>,
    #[serde(default)]
    pub last_success_ms: Option<i64>,
    /// Events the sink accepted, all told.
    #[serde(default)]
    pub delivered: u64,
    /// Events skipped because the sink fell too far behind, all told.
    #[serde(default)]
    pub skipped: u64,
    /// Gaps recorded and not yet accepted by the sink: sent with the next
    /// request, whatever it carries.
    #[serde(default)]
    pub gaps: Vec<Gap>,
}

impl State {
    pub fn path(home: &Home, sink: &str) -> PathBuf {
        home.delivery_dir().join(format!("{sink}.json"))
    }

    /// The sink's state; a missing file is a sink that never ran.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    /// Whether a run that no person asked for may try now.
    pub fn due(&self, now_ms: i64) -> bool {
        self.paused.is_none() && now_ms >= self.next_attempt_ms
    }

    /// The sink accepted every event up to `last` and the gaps sent with them.
    pub fn accepted(&mut self, last: Option<EventId>, events: u64, now_ms: i64) {
        if let Some(last) = last {
            self.cursor = Some(last);
        }
        self.delivered = self.delivered.saturating_add(events);
        self.gaps.clear();
        self.failures = 0;
        self.next_attempt_ms = 0;
        self.paused = None;
        self.last_success_ms = Some(now_ms);
    }

    /// A failure that may pass: wait, longer each time, or as the sink asked.
    /// `jitter` (0 to 1) spreads machines that failed together.
    pub fn failed(&mut self, why: String, retry_after_s: Option<u64>, now_ms: i64, jitter: f64) {
        self.failures = self.failures.saturating_add(1);
        let wait = backoff(self.failures, retry_after_s, jitter);
        self.next_attempt_ms = now_ms.saturating_add(i64::try_from(wait.as_millis()).unwrap_or(0));
        self.last_error = Some(why);
        self.last_error_ms = Some(now_ms);
    }

    /// An answer that trying again cannot change.
    pub fn pause(&mut self, why: String, now_ms: i64) {
        self.failures = self.failures.saturating_add(1);
        self.paused = Some(why.clone());
        self.last_error = Some(why);
        self.last_error_ms = Some(now_ms);
    }
}

/// A sink's cursor in its state file: lowercase hex as every event id, and
/// `0`, the place before the first event where a sink that starts with the
/// whole log, or with an empty one, stands until it accepts an event.
mod cursor {
    use openmoat_audit::EventId;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    #[expect(
        clippy::ref_option,
        reason = "serde's `with` passes the field by reference"
    )]
    pub fn serialize<S: Serializer>(cursor: &Option<EventId>, out: S) -> Result<S::Ok, S::Error> {
        match cursor {
            Some(id) => out.serialize_some(&id.to_string()),
            None => out.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Option<EventId>, D::Error> {
        let Some(text) = Option::<String>::deserialize(input)? else {
            return Ok(None);
        };
        i64::from_str_radix(&text, 16)
            .ok()
            .filter(|id| *id >= 0)
            .map(|id| Some(EventId(id)))
            .ok_or_else(|| D::Error::custom(format!("invalid cursor `{text}`; expected hex")))
    }
}

/// `FIRST_WAIT` doubled per failure after the first, at most `MAX_WAIT`, plus
/// up to a fifth more by `jitter`; a longer `Retry-After` wins, up to an hour.
pub fn backoff(failures: u32, retry_after_s: Option<u64>, jitter: f64) -> Duration {
    let doubled = FIRST_WAIT.saturating_mul(1u32 << failures.saturating_sub(1).min(16));
    let base = doubled.min(MAX_WAIT);
    let spread = base.mul_f64(jitter.clamp(0.0, 1.0) / 5.0);
    let asked = retry_after_s
        .map(Duration::from_secs)
        .unwrap_or_default()
        .min(MAX_RETRY_AFTER);
    (base + spread).max(asked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_to_a_cap_and_a_longer_retry_after_wins() {
        assert_eq!(backoff(1, None, 0.0), FIRST_WAIT);
        assert_eq!(backoff(2, None, 0.0), FIRST_WAIT * 2);
        assert_eq!(backoff(4, None, 0.0), FIRST_WAIT * 8);
        assert_eq!(backoff(30, None, 0.0), MAX_WAIT);
        assert_eq!(backoff(u32::MAX, None, 1.0), MAX_WAIT + MAX_WAIT / 5);
        assert_eq!(backoff(1, Some(120), 0.0), Duration::from_secs(120));
        assert_eq!(backoff(1, Some(1), 0.0), FIRST_WAIT);
        assert_eq!(backoff(1, Some(u64::MAX), 0.0), MAX_RETRY_AFTER);
    }

    #[test]
    fn a_failure_waits_a_refusal_pauses_and_a_success_clears_both() {
        let mut state = State::default();
        assert!(state.due(0));
        state.failed("HTTP 503".to_owned(), None, 1_000, 0.0);
        assert!(!state.due(1_000));
        assert!(state.due(6_000));
        state.pause("HTTP 401".to_owned(), 7_000);
        assert!(!state.due(i64::MAX));
        state.gaps.push(Gap {
            first: EventId(1),
            last: EventId(2),
            count: 2,
            reason: openmoat_audit::delivery::GapReason::BacklogFull,
        });
        state.accepted(Some(EventId(9)), 3, 8_000);
        assert!(state.due(8_000));
        assert_eq!(state.cursor, Some(EventId(9)));
        assert_eq!((state.failures, state.delivered), (0, 3));
        assert_eq!(state.gaps, Vec::new());
        assert_eq!(state.paused, None);
        // The failure stays for `status`.
        assert_eq!(state.last_error.as_deref(), Some("HTTP 401"));
    }

    /// Every state a run saves reads back as it was: before the first run,
    /// at the start with no event sent (cursor `0`), after a failure there,
    /// and after a success with a gap.
    #[test]
    fn every_saved_state_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.json");
        let fresh = State::default();
        let mut start = State {
            cursor: Some(EventId(0)),
            ..State::default()
        };
        let empty = start.clone();
        start.failed("HTTP 503".to_owned(), Some(30), 1_000, 0.5);
        let failed = start.clone();
        let mut done = failed.clone();
        done.gaps.push(Gap {
            first: EventId(1),
            last: EventId(0x1f),
            count: 31,
            reason: openmoat_audit::delivery::GapReason::BacklogFull,
        });
        done.accepted(Some(EventId(0x2a)), 11, 2_000);
        for state in [fresh, empty, failed, done] {
            state.save(&path).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(State::load(&path).unwrap(), state, "{text}");
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(r#""cursor": "2a""#), "{text}");
        std::fs::write(&path, r#"{"cursor": "-1"}"#).unwrap();
        assert!(State::load(&path).is_err());
    }
}
