//! Connections refused at accept for capacity, in the audit log.
//!
//! A connection over `max_connections`, or over the share of those not yet
//! authenticated, is answered 503 before its head is read. Each is a
//! refusal whether or not it is recorded; recording every one would let a
//! flood fill the log, so the first refusal of a kind is recorded at once and
//! the ones after it are counted and recorded as one row per [`INTERVAL`],
//! when the next connection is accepted or refused after it.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use openmoat_core::{Decision, Verdict};

use crate::audit::{Connection, Recorder};

/// Rule id for a connection refused at accept because the proxy, or the
/// connections not yet authenticated, hold all the slots they may.
pub const RULE_CAPACITY: &str = "proxy-capacity";

/// The shortest time between two rows of one kind.
pub(super) const INTERVAL: Duration = Duration::from_secs(10);

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Full {
    /// Every slot is taken.
    Slots,
    /// The connections not yet authenticated hold their share.
    Pending,
}

impl Full {
    /// What the 503 says.
    pub(super) fn reply(self) -> &'static str {
        match self {
            Self::Slots => "too many connections",
            Self::Pending => "too many connections waiting to authenticate",
        }
    }
}

/// Per kind: when a row was last written, and the refusals not in a row yet.
#[derive(Debug, Default)]
struct Kind {
    last: Option<Instant>,
    unrecorded: u64,
}

/// The refusals at accept of one [`Proxy::serve`](crate::Proxy::serve).
#[derive(Debug, Default)]
pub(super) struct Refusals {
    kinds: Mutex<[Kind; 2]>,
}

impl Refusals {
    /// Count one refusal, and record the count once [`INTERVAL`] has passed
    /// since the last row of its kind.
    pub(super) fn refused(&self, full: Full, recorder: &dyn Recorder, now: Instant) {
        let due = {
            let mut kinds = self.kinds.lock().unwrap_or_else(PoisonError::into_inner);
            let kind = &mut kinds[full as usize];
            kind.unrecorded += 1;
            take_due(kind, now)
        };
        if let Some(count) = due {
            write(full, count, recorder);
        }
    }

    /// Record the refusals counted since the last row, where [`INTERVAL`] has
    /// passed: called as connections are accepted, so a burst that ends is
    /// still recorded.
    pub(super) fn flush(&self, recorder: &dyn Recorder, now: Instant) {
        let due: Vec<(Full, u64)> = {
            let mut kinds = self.kinds.lock().unwrap_or_else(PoisonError::into_inner);
            [Full::Slots, Full::Pending]
                .into_iter()
                .filter_map(|full| {
                    let kind = &mut kinds[full as usize];
                    (kind.unrecorded > 0)
                        .then(|| take_due(kind, now))
                        .flatten()
                        .map(|n| (full, n))
                })
                .collect()
        };
        for (full, count) in due {
            write(full, count, recorder);
        }
    }
}

/// The count to record now, if [`INTERVAL`] has passed since the last row.
fn take_due(kind: &mut Kind, now: Instant) -> Option<u64> {
    let due = kind
        .last
        .is_none_or(|last| now.saturating_duration_since(last) >= INTERVAL);
    if !due {
        return None;
    }
    kind.last = Some(now);
    Some(std::mem::take(&mut kind.unrecorded))
}

fn write(full: Full, count: u64, recorder: &dyn Recorder) {
    let plural = if count == 1 { "" } else { "s" };
    let decision = Decision::single(
        Verdict::Deny,
        RULE_CAPACITY,
        format!(
            "{count} connection{plural} refused before a request was read: {}; later ones \
             within {} s are counted in the next row",
            full.reply(),
            INTERVAL.as_secs()
        ),
    );
    let connection = Connection {
        session: None,
        method: None,
        destination: None,
        decision: &decision,
        latency_us: 0,
    };
    // The connections are refused either way; a row that cannot be written
    // is reported where the recorder reports failures.
    if let Err(error) = recorder.record(&connection) {
        recorder.unrecorded(&error);
    }
}

#[cfg(test)]
mod tests;
