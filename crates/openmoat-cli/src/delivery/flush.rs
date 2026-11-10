//! A delivery run: each sink that is due gets the events after its cursor,
//! in batches, until it has them all, fails, or the run's time is up
//! (ADR-081).
//!
//! The audit log is the queue. A sink that falls more than `max_backlog`
//! events behind skips the oldest down to nine tenths of it; the skip is
//! recorded in the audit log as an event of its own (rule
//! [`OVERFLOW_RULE`]) and sent to the sink as a gap with its next request,
//! so nothing is left out unseen. The skipped events stay in the local log.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use openmoat_audit::delivery::{self, Gap, GapReason, Origin};
use openmoat_audit::{EventId, KnownSecrets, NewEvent, Store};
use openmoat_core::{Decision, Verdict};

use super::config::{Config, Sink, Start};
use super::send::{Ready, Sent};
use super::state::State;
use crate::home::Home;
use crate::time;

/// Rule id of the audit event that records a skip.
pub const OVERFLOW_RULE: &str = "audit-delivery-overflow";
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
            ready: &ready,
            known: &known,
        };
        if state.cursor.is_none() {
            state.cursor = Some(start(&store, config.start, accepted_ms)?);
        }
        sink_run.drain(&mut state, &mut run, &path, || started.elapsed() < budget)?;
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
    ready: &'a Ready,
    known: &'a KnownSecrets,
}

impl Sinking<'_> {
    /// Send batch after batch while `go_on` says so, saving the state after
    /// each answer.
    fn drain(
        &self,
        state: &mut State,
        run: &mut SinkRun,
        path: &std::path::Path,
        go_on: impl Fn() -> bool,
    ) -> Result<()> {
        let origin = Origin {
            machine: &self.config.machine,
            version: env!("CARGO_PKG_VERSION"),
        };
        while go_on() {
            run.skipped += self.overflow(state)?;
            state.save(path)?;
            let cursor = state.cursor.unwrap_or(EventId(0));
            let events = self.store.export_after(cursor, BATCH_EVENTS)?;
            if events.is_empty() && state.gaps.is_empty() {
                return Ok(());
            }
            let records = delivery::pack(&events, self.known, self.config.batch_bytes)?;
            let now = time::now_ms();
            match self
                .ready
                .send(self.sink, origin, &records, &state.gaps, now)?
            {
                Sent::Accepted => {
                    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
                    state.accepted(records.last().map(|r| r.id), count, now);
                    run.delivered += count;
                    state.save(path)?;
                }
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
        record_overflow(self.store, &self.sink.id, &gap)?;
        state.cursor = Some(skip_to);
        state.skipped = state.skipped.saturating_add(count);
        state.gaps.push(gap);
        Ok(count)
    }
}

/// The skip as an audit event: host [`DELIVERY_HOST`], the sink as its
/// session, rule [`OVERFLOW_RULE`]. Verdict `defer`: it decides no call.
fn record_overflow(store: &Store, sink: &str, gap: &Gap) -> Result<()> {
    let decision = Decision::single(Verdict::Defer, OVERFLOW_RULE, gap.describe());
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
