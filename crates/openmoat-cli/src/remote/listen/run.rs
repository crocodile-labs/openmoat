//! The two halves of `openmoat approvals listen` (ADR-093), each on its own
//! thread with its own [`Channel`]:
//!
//! - [`sending`] looks at the request store every [`SEND_EVERY`], sends each
//!   new request to the approvers at once, expires the old ones, and writes
//!   the listener's beat ([`super::super::live`]) every [`BEAT_EVERY`] while
//!   the channel answers;
//! - [`answering`] polls the channel, waiting on its server as long as the
//!   channel allows ([`Capabilities::poll_wait`](super::super::channel::Capabilities)),
//!   so a reply is seen the moment it arrives, and answers each one.
//!
//! A poll in flight does not stop the beat: the sending half writes it, so
//! a long poll never makes a live listener look stale. Polls that fail, or
//! an answering half that stopped polling, do: the beat is written only
//! while the last successful poll ended within the channel's `poll_wait`
//! plus [`POLL_SLACK`] ([`Shared::answers`]). An answering half that ends
//! for any reason, a panic included, stops `listen`. Ctrl-C sets
//! [`Shared::stop`]; the sending half removes the beat and returns, after
//! any reply being answered is finished ([`Shared::finish`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;

use super::super::channel::Channel;
use super::super::settings::Settings;
use super::{Listener, Records};

/// How often the sending half looks for new requests.
pub const SEND_EVERY: Duration = Duration::from_secs(1);
/// How often it writes the beat, well inside a beat's life.
pub const BEAT_EVERY: Duration = Duration::from_secs(3);
const _: () = assert!(
    BEAT_EVERY.as_secs() * 4 < super::super::live::LIVE_MS.unsigned_abs() / 1000,
    "several beats fit in a beat's life"
);
/// The pause between polls of a channel whose poll returns at once.
pub const POLL_PAUSE: Duration = Duration::from_secs(2);
/// The pause after a failed poll, so a channel that is down is not hammered.
pub const BACKOFF: Duration = Duration::from_secs(5);
/// What a poll may take beyond the wait it asks for (connecting, a slow
/// network) before the listener stops counting as one that answers.
pub const POLL_SLACK: Duration = Duration::from_secs(15);
/// How finely a pause checks [`Shared::stop`].
const TICK: Duration = Duration::from_millis(100);

/// What the two halves share.
pub struct Shared {
    /// Set by Ctrl-C, or by a half that stops.
    pub stop: Arc<AtomicBool>,
    /// When the last poll of the channel succeeded, or the listener started.
    polled: Mutex<Instant>,
    /// Held while replies are answered, so a stop never cuts one short.
    answering: Mutex<()>,
}

impl Shared {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            polled: Mutex::new(Instant::now()),
            answering: Mutex::new(()),
        }
    }

    /// Whether the channel answers: its last poll succeeded within `wait`
    /// plus [`POLL_SLACK`], `wait` being the channel's `poll_wait`, or
    /// [`POLL_PAUSE`] when it has none.
    pub fn answers(&self, wait: Duration) -> bool {
        let wait = if wait.is_zero() { POLL_PAUSE } else { wait };
        self.polled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
            <= wait + POLL_SLACK
    }

    /// Stop both halves now.
    pub fn halt(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn polled_now(&self) {
        *self.polled.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Stop both halves and wait for replies being answered, if any; until
    /// the guard returned is dropped no new ones are.
    pub fn finish(&self) -> MutexGuard<'_, ()> {
        self.stop.store(true, Ordering::Relaxed);
        self.answering
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Sleep `span`, or less once stopped; whether it was stopped.
    fn pause(&self, span: Duration) -> bool {
        let until = Instant::now() + span;
        while !self.stopped() {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            std::thread::sleep(left.min(TICK));
        }
        true
    }
}

/// Where a half's lines go, one per event, for the person's terminal.
pub type Log<'a> = &'a (dyn Fn(&str) + Sync);

/// The sending half, until stopped: every [`SEND_EVERY`], `refresh` reads the
/// settings (an error, such as another channel connected, stops both
/// halves), then requests are sent and expired; the beat is written every
/// [`BEAT_EVERY`] while the channel is healthy. Removes the beat when it
/// returns, once replies being answered are done.
pub fn sending(
    listener: &mut Listener<'_>,
    (channel, records): (&mut dyn Channel, &mut dyn Records),
    shared: &Shared,
    refresh: &dyn Fn() -> Result<Settings>,
    log: Log<'_>,
) -> Result<()> {
    let result = send_loop(listener, (channel, records), shared, refresh, log);
    let _done = shared.finish();
    super::super::live::stop(listener.store);
    result
}

fn send_loop(
    listener: &mut Listener<'_>,
    (channel, records): (&mut dyn Channel, &mut dyn Records),
    shared: &Shared,
    refresh: &dyn Fn() -> Result<Settings>,
    log: Log<'_>,
) -> Result<()> {
    let mut beat_at: Option<Instant> = None;
    loop {
        listener.update(refresh()?);
        let round = listener.send_round(channel, records, &crate::time::now_ms);
        for line in listener.log.drain(..) {
            log(&line);
        }
        match round {
            Err(error) => log(&format!("{error:#}")),
            Ok(()) if shared.answers(listener.spec().capabilities.poll_wait) => {
                if beat_at.is_none_or(|at| at.elapsed() >= BEAT_EVERY) {
                    listener.beat(crate::time::now_ms());
                    beat_at = Some(Instant::now());
                }
            }
            Ok(()) => {
                // A listener that cannot reach its channel is no listener:
                // the beat goes stale and guards stop waiting.
                beat_at = None;
            }
        }
        if shared.pause(SEND_EVERY) {
            return Ok(());
        }
    }
}

/// The answering half, until stopped: poll, then, holding the answering lock,
/// read the settings again (`refresh`) and answer every reply. A failed poll
/// marks the channel unhealthy and is retried after [`BACKOFF`].
pub fn answering(
    listener: &mut Listener<'_>,
    (channel, records): (&mut dyn Channel, &mut dyn Records),
    shared: &Shared,
    refresh: &dyn Fn() -> Result<Settings>,
    log: Log<'_>,
) {
    // However this half ends, a panic included, `listen` stops with it: a
    // listener that no longer answers must not keep a beat.
    let _stops = StopOnDrop(shared);
    let wait = listener.spec().capabilities.poll_wait;
    while !shared.stopped() {
        let polled = channel.poll(wait);
        let answered = {
            let _answering = shared
                .answering
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if shared.stopped() {
                return;
            }
            polled.and_then(|replies| {
                listener.update(refresh()?);
                listener.answer(channel, records, &replies, &crate::time::now_ms)
            })
        };
        for line in listener.log.drain(..) {
            log(&line);
        }
        let pause = match answered {
            Ok(()) => {
                shared.polled_now();
                if wait.is_zero() {
                    POLL_PAUSE
                } else {
                    Duration::ZERO
                }
            }
            Err(error) => {
                log(&format!(
                    "{error:#}; trying again in {} s",
                    BACKOFF.as_secs()
                ));
                BACKOFF
            }
        };
        if shared.pause(pause) {
            return;
        }
    }
}

/// Sets [`Shared::stop`] when dropped.
struct StopOnDrop<'a>(&'a Shared);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.halt();
    }
}
