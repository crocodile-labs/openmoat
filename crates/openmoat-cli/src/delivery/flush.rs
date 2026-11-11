//! A delivery run: each sink that is due gets the events after its cursor,
//! in batches, until it has them all, fails, or the run's time is up
//! (ADR-081).
//!
//! The audit log is the queue. A sink that falls more than `max_backlog`
//! events behind skips the oldest down to nine tenths of it; the skip is
//! recorded in the audit log as an event of its own (rule
//! [`OVERFLOW_RULE`]) and sent to the sink as a gap with its next request,
//! so nothing is left out unseen. The skipped events stay in the local log.
//!
//! Each event is trimmed before it is sent (`delivery::pack`). A sink that
//! still answers `413` gets half as many events per request; one event alone
//! that gets `413` is skipped the same way (rule [`TOO_LARGE_RULE`]), so one
//! event never pauses a sink.
//!
//! An OTLP collector that accepts a request but rejects some of its records
//! (`partial_success`) must not be sent them again: the cursor moves on, and
//! the loss is recorded (rule [`PARTIAL_RULE`]) and sent as a gap.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use openmoat_audit::delivery::{self, Delivered, Gap, GapReason, Origin};
use openmoat_audit::{EventId, KnownSecrets, NewEvent, Store};
use openmoat_core::{Decision, Verdict};

use super::config::{Config, Sink, Start};
use super::send::{Ready, Sent};
use super::state::State;
use crate::home::Home;
use crate::time;

/// Rule id of the audit event that records a skip.
pub const OVERFLOW_RULE: &str = "audit-delivery-overflow";
/// Rule id of the audit event that records an event the sink refused as too
/// large (`413`) even alone.
pub const TOO_LARGE_RULE: &str = "audit-delivery-too-large";
/// Rule id of the audit event that records log records an OTLP collector
/// accepted the request without (`partial_success`).
pub const PARTIAL_RULE: &str = "audit-delivery-partial";
/// The most characters of a collector's own message kept.
const MAX_MESSAGE_CHARS: usize = 300;
/// Host id of the events delivery itself records.
pub const DELIVERY_HOST: &str = "audit-delivery";

/// The most events read for one request; `batch_bytes` may take fewer.
const BATCH_EVENTS: usize = 500;

/// What one sink's part of a run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SinkRun {
    pub sink: String,
    /// Events the sink accepted in this run.
    pub delivered: u64,
    /// Events skipped in this run.
    pub skipped: u64,
    /// Why it stopped early, if it did.
    pub stopped: Option<String>,
    /// Not due: waiting after a failure, or paused.
    pub waiting: bool,
}

/// Run every sink of `config` that is due (all of them when `forced`, a
/// person's `flush`) until done or `budget` is spent.
pub fn run(
    home: &Home,
    config: &Config,
    accepted_ms: i64,
    forced: bool,
    budget: Duration,
) -> Result<Vec<SinkRun>> {
    let started = Instant::now();
    let store = Store::open_existing(&home.audit_path())
        .with_context(|| format!("opening {}", home.audit_path().display()))?;
    let user_home = crate::home::user_home()?.to_string_lossy().into_owned();
    // Fail closed: without the policy's secrets the bodies cannot be masked.
    let policy = home.load_policy()?;
    let mut runs = Vec::new();
    for sink in &config.sinks {
        let path = State::path(home, &sink.id);
        let mut state = State::load(&path)?;
        let mut run = SinkRun {
            sink: sink.id.clone(),
            ..SinkRun::default()
        };
        if !forced && !state.due(time::now_ms()) {
            run.waiting = true;
            runs.push(run);
            continue;
        }
        if forced {
            state.paused = None;
        }
        let ready = match Ready::new(sink, &user_home) {
            Ok(ready) => ready,
            Err(e) => {
                state.failed(format!("{e:#}"), None, time::now_ms(), jitter());
                state.save(&path)?;
                run.stopped.clone_from(&state.last_error);
                runs.push(run);
                continue;
            }
        };
        let policy_values = crate::secrets::known_values(&policy.secrets, &user_home);
        let known = KnownSecrets::new(
            policy_values
                .iter()
                .map(|v| v.as_str())
                .chain(ready.values()),
        )?;
        let sink_run = Sinking {
            store: &store,
            config,
            sink,
            known: &known,
        };
        if state.cursor.is_none() {
            state.cursor = Some(start(&store, config.start, accepted_ms)?);
        }
        let origin = Origin {
            machine: &config.machine,
            version: env!("CARGO_PKG_VERSION"),
        };
        sink_run.drain(
            &mut state,
            &mut run,
            &path,
            || started.elapsed() < budget,
            |records, gaps, now| ready.send(sink, origin, records, gaps, now),
        )?;
        runs.push(run);
    }
    Ok(runs)
}

/// Where a new sink starts: before the first event, or at the last event
/// recorded before the configuration was accepted.
fn start(store: &Store, start: Start, accepted_ms: i64) -> Result<EventId> {
    Ok(match start {
        Start::All => EventId(0),
        Start::New => store.last_before(accepted_ms)?.unwrap_or(EventId(0)),
    })
}

struct Sinking<'a> {
    store: &'a Store,
    config: &'a Config,
    sink: &'a Sink,
    known: &'a KnownSecrets,
}

impl Sinking<'_> {
    /// Send batch after batch with `send` while `go_on` says so, saving the
    /// state after each answer.
    fn drain(
        &self,
        state: &mut State,
        run: &mut SinkRun,
        path: &std::path::Path,
        go_on: impl Fn() -> bool,
        send: impl Fn(&[Delivered], &[Gap], i64) -> Result<Sent>,
    ) -> Result<()> {
        // Halved after each `413`, for the rest of this run.
        let mut batch_events = BATCH_EVENTS;
        while go_on() {
            run.skipped += self.overflow(state)?;
            state.save(path)?;
            let cursor = state.cursor.unwrap_or(EventId(0));
            let events = self.store.export_after(cursor, batch_events)?;
            if events.is_empty() && state.gaps.is_empty() {
                return Ok(());
            }
            let records = delivery::pack(&events, self.known, self.config.batch_bytes)?;
            let now = time::now_ms();
            match send(&records, &state.gaps, now)? {
                Sent::Accepted => {
                    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
                    state.accepted(records.last().map(|r| r.id), count, now);
                    run.delivered += count;
                    state.save(path)?;
                }
                Sent::Partial(rejected) => {
                    // The collector's count, at most what the request held.
                    let in_request =
                        u64::try_from(records.len() + state.gaps.len()).unwrap_or(u64::MAX);
                    let lost = rejected.count.min(in_request);
                    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
                    let kept = count.saturating_sub(lost);
                    state.accepted(records.last().map(|r| r.id), kept, now);
                    run.delivered += kept;
                    run.skipped += self.rejected(state, &records, lost, &rejected.message, now)?;
                    state.save(path)?;
                }
                Sent::TooLarge => match records.as_slice() {
                    // Only the gaps went, a few hundred bytes: the sink's
                    // limit may be a passing one.
                    [] => {
                        state.failed("HTTP 413".to_owned(), None, now, jitter());
                        state.save(path)?;
                        run.stopped.clone_from(&state.last_error);
                        return Ok(());
                    }
                    [only] => {
                        run.skipped += self.skip_too_large(state, only.id)?;
                        state.save(path)?;
                    }
                    more => batch_events = more.len() / 2,
                },
                Sent::Retry { why, retry_after_s } => {
                    state.failed(why, retry_after_s, now, jitter());
                    state.save(path)?;
                    run.stopped.clone_from(&state.last_error);
                    return Ok(());
                }
                Sent::Refused { why } => {
                    state.pause(why, now);
                    state.save(path)?;
                    run.stopped.clone_from(&state.last_error);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// When the sink is more than `max_backlog` events behind, skip the
    /// oldest down to nine tenths of it, record the skip, and keep the gap to
    /// send. The number of events skipped.
    fn overflow(&self, state: &mut State) -> Result<u64> {
        let Some(head) = self.store.latest_id()? else {
            return Ok(0);
        };
        let cursor = state.cursor.unwrap_or(EventId(0));
        let max = i64::try_from(self.config.max_backlog).unwrap_or(i64::MAX);
        if head.0.saturating_sub(cursor.0) <= max {
            return Ok(0);
        }
        // Room for the events that arrive while the sink catches up, and for
        // the row that records this skip.
        let keep = max - max / 10;
        let skip_to = EventId(head.0 - keep);
        let count = self.store.count_between(cursor, skip_to)?;
        let gap = Gap {
            first: EventId(cursor.0 + 1),
            last: skip_to,
            count,
            reason: GapReason::BacklogFull,
        };
        record_skip(self.store, &self.sink.id, OVERFLOW_RULE, &gap.describe())?;
        state.cursor = Some(skip_to);
        state.skipped = state.skipped.saturating_add(count);
        state.gaps.push(gap);
        Ok(count)
    }

    /// The sink refused event `id` as too large even alone (and trimmed,
    /// `delivery::MAX_EVENT_BYTES`): skip it, record the skip, and keep the
    /// gap to send, as an overflow does. Never a pause: one event must not
    /// stop the sink for good. The number of events skipped.
    fn skip_too_large(&self, state: &mut State, id: EventId) -> Result<u64> {
        let gap = Gap {
            first: id,
            last: id,
            count: 1,
            reason: GapReason::TooLarge,
        };
        record_skip(self.store, &self.sink.id, TOO_LARGE_RULE, &gap.describe())?;
        state.cursor = Some(id);
        state.skipped = state.skipped.saturating_add(1);
        state.gaps.push(gap);
        Ok(1)
    }

    /// An OTLP collector accepted the request with `records` but rejected
    /// `rejected` of its log records, which it says must not be sent again:
    /// the cursor has moved past them, so record the loss and keep it as a
    /// gap to send, as a skip is. `message`, the collector's text, is masked
    /// with the policy's and the sink's own secrets (a collector may echo a
    /// header), then cut, so no cut leaves part of a secret. A request of
    /// delivery's own rows alone is counted but not recorded again, so a
    /// collector that rejects every record cannot make the log grow by
    /// itself. The number of events lost.
    fn rejected(
        &self,
        state: &mut State,
        records: &[Delivered],
        rejected: u64,
        message: &str,
        now_ms: i64,
    ) -> Result<u64> {
        let flat: String = message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let masked: String = self
            .known
            .redact(&flat)
            .trim()
            .chars()
            .take(MAX_MESSAGE_CHARS)
            .collect();
        let why = if masked.is_empty() {
            format!("the collector rejected {rejected} log record(s)")
        } else {
            format!("the collector rejected {rejected} log record(s): {masked}")
        };
        state.last_error = Some(why.clone());
        state.last_error_ms = Some(now_ms);
        let (Some(first), Some(newest)) = (records.first(), records.last()) else {
            // Only gaps went: no event is lost, the gaps' records are.
            return Ok(0);
        };
        let lost = rejected.min(u64::try_from(records.len()).unwrap_or(u64::MAX));
        let gap = Gap {
            first: first.id,
            last: newest.id,
            count: lost,
            reason: GapReason::Rejected,
        };
        if records.iter().any(|r| r.host != DELIVERY_HOST) {
            let reason = format!("{} ({why})", gap.describe());
            record_skip(self.store, &self.sink.id, PARTIAL_RULE, &reason)?;
        }
        state.skipped = state.skipped.saturating_add(lost);
        state.gaps.push(gap);
        Ok(lost)
    }
}

/// A skip as an audit event: host [`DELIVERY_HOST`], the sink as its
/// session, `rule` ([`OVERFLOW_RULE`], [`TOO_LARGE_RULE`] or
/// [`PARTIAL_RULE`]) and `reason`. Verdict `defer`: it decides no call.
fn record_skip(store: &Store, sink: &str, rule: &str, reason: &str) -> Result<()> {
    let decision = Decision::single(Verdict::Defer, rule, reason.to_owned());
    store
        .record(&NewEvent {
            host: DELIVERY_HOST,
            session_id: sink,
            call_id: None,
            cwd: None,
            tool: "deliver",
            action: None,
            decision: &decision,
            latency_us: 0,
        })
        .context("recording the skipped events in the audit log")?;
    Ok(())
}

/// A number from 0 to 1 from the OS's random source, 0 when it cannot be read.
fn jitter() -> f64 {
    let mut byte = [0u8; 1];
    match getrandom::fill(&mut byte) {
        Ok(()) => f64::from(byte[0]) / 255.0,
        Err(_) => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use openmoat_core::Action;

    use super::*;

    fn record(store: &Store, command: &str) {
        let decision = Decision::single(Verdict::Allow, "dev-shell", "ok");
        let action = Action::Shell {
            command: command.to_owned(),
        };
        store
            .record(&NewEvent {
                host: "some-agent",
                session_id: "s1",
                call_id: None,
                cwd: None,
                tool: "Bash",
                action: Some(&action),
                decision: &decision,
                latency_us: 1,
            })
            .unwrap();
    }

    /// A sink that answers `413` to any request holding the event `BIG`, alone
    /// or not: it gets the events before and after it, a gap for it, and is
    /// never paused.
    #[test]
    fn an_event_a_sink_refuses_as_too_large_is_skipped_not_a_pause() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let config = super::super::config::parse(
            "version: 1\nmachine: m\nstart: all\nsinks:\n  - id: c\n    otlp: \
             http://127.0.0.1:9/v1/logs\n",
            &home,
        )
        .unwrap();
        let store = Store::open_in_memory().unwrap();
        for command in ["echo one", "echo BIG", "echo three"] {
            record(&store, command);
        }
        let known = KnownSecrets::default();
        let sinking = Sinking {
            store: &store,
            config: &config,
            sink: &config.sinks[0],
            known: &known,
        };
        let delivered = RefCell::new(Vec::new());
        let gaps_sent = RefCell::new(Vec::new());
        let send = |records: &[Delivered], gaps: &[Gap], _now: i64| {
            if records.iter().any(|r| r.action.to_string().contains("BIG")) {
                return Ok(Sent::TooLarge);
            }
            delivered
                .borrow_mut()
                .extend(records.iter().map(|r| r.action.to_string()));
            gaps_sent.borrow_mut().extend(gaps.iter().cloned());
            Ok(Sent::Accepted)
        };
        let mut state = State {
            cursor: Some(EventId(0)),
            ..State::default()
        };
        let mut run = SinkRun::default();
        let path = dir.path().join("c.json");
        sinking
            .drain(&mut state, &mut run, &path, || true, send)
            .unwrap();
        assert_eq!(state.paused, None, "{state:?}");
        assert_eq!((run.skipped, state.skipped), (1, 1), "{run:?}");
        let delivered = delivered.into_inner();
        assert!(
            delivered.iter().any(|a| a.contains("echo one")),
            "{delivered:?}"
        );
        assert!(
            delivered.iter().any(|a| a.contains("echo three")),
            "{delivered:?}"
        );
        assert!(
            !delivered.iter().any(|a| a.contains("BIG")),
            "{delivered:?}"
        );
        let gaps = gaps_sent.into_inner();
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!((gaps[0].reason, gaps[0].count), (GapReason::TooLarge, 1));
        assert_eq!(state.gaps, Vec::new(), "the gap was accepted");
        let rules: Vec<String> = store
            .export_after(EventId(0), 10)
            .unwrap()
            .iter()
            .map(|e| e.rules.get().to_owned())
            .collect();
        assert!(
            rules.iter().any(|r| r.contains(TOO_LARGE_RULE)),
            "{rules:?}"
        );
    }

    /// A collector that accepts every request but rejects one record of each
    /// (`partial_success`), echoing the sink's token: the cursor moves on,
    /// the loss is recorded once, masked, and sent as a gap; its own row
    /// rejected again is counted, not recorded again, so the run ends.
    #[test]
    fn records_a_collector_rejects_are_recorded_once_and_sent_as_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let config = super::super::config::parse(
            "version: 1\nmachine: m\nstart: all\nsinks:\n  - id: c\n    otlp: \
             http://127.0.0.1:9/v1/logs\n",
            &home,
        )
        .unwrap();
        let store = Store::open_in_memory().unwrap();
        for command in ["echo one", "echo two"] {
            record(&store, command);
        }
        // Matches no built-in pattern: only the sink's own values mask it.
        let token = format!("collector{}token{}", "-plain-", 777);
        let known = KnownSecrets::new([token.as_str()]).unwrap();
        let sinking = Sinking {
            store: &store,
            config: &config,
            sink: &config.sinks[0],
            known: &known,
        };
        let requests = RefCell::new(Vec::new());
        let send = |records: &[Delivered], gaps: &[Gap], _now: i64| {
            let hosts: Vec<String> = records.iter().map(|r| r.host.clone()).collect();
            requests.borrow_mut().push((hosts, gaps.to_vec()));
            Ok(Sent::Partial(delivery::Rejected {
                count: 1,
                message: format!("record too old\nAuthorization: Bearer {token}"),
            }))
        };
        let mut state = State {
            cursor: Some(EventId(0)),
            ..State::default()
        };
        let mut run = SinkRun::default();
        let path = dir.path().join("c.json");
        sinking
            .drain(&mut state, &mut run, &path, || true, send)
            .unwrap();
        let requests = requests.into_inner();
        // The events; the row of the loss with its gap; the gap of that row.
        assert_eq!(requests.len(), 3, "{requests:?}");
        assert_eq!(requests[0].0, ["some-agent", "some-agent"]);
        assert_eq!(requests[1].0, [DELIVERY_HOST]);
        assert_eq!(requests[1].1.len(), 1);
        assert_eq!(
            (requests[1].1[0].reason, requests[1].1[0].count),
            (GapReason::Rejected, 1)
        );
        assert_eq!(
            (requests[1].1[0].first, requests[1].1[0].last),
            (EventId(1), EventId(2))
        );
        assert!(requests[2].0.is_empty(), "{requests:?}");
        assert_eq!(state.cursor, Some(EventId(3)), "{state:?}");
        assert_eq!((state.delivered, state.skipped, run.skipped), (1, 2, 2));
        assert_eq!(state.paused, None);
        let events = store.export_after(EventId(0), 10).unwrap();
        let partial: Vec<String> = events
            .iter()
            .filter(|e| e.rules.get().contains(PARTIAL_RULE))
            .map(|e| e.reasons.get().to_owned())
            .collect();
        assert_eq!(partial.len(), 1, "{partial:?}");
        assert!(partial[0].contains("record too old"), "{partial:?}");
        assert!(!partial[0].contains(&token), "{partial:?}");
        assert!(!partial[0].contains('\n'), "{partial:?}");
        let last_error = state.last_error.unwrap_or_default();
        assert!(!last_error.contains(&token), "{last_error}");
    }
}
