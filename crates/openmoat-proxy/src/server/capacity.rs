//! Connections refused at accept for capacity, in the audit log.
//!
//! A connection over `max_connections`, or over the share of those not yet
//! authenticated, is answered 503 before its head is read. Each is a
//! refusal whether or not it is recorded; recording every one would let a
//! flood fill the log, so the first refusal of a kind is recorded at once and
//! the ones after it are counted and recorded as one row per [`INTERVAL`],
//! when the next connection is accepted or refused after it
//! ([`crate::coalesce`]).

use std::time::Instant;

use openmoat_core::{Decision, Verdict};

use crate::audit::{Connection, Recorder};
pub(super) use crate::coalesce::INTERVAL;
use crate::coalesce::{Coalesce, counted};

/// Rule id for a connection refused at accept because the proxy, or the
/// connections not yet authenticated, hold all the slots they may.
pub const RULE_CAPACITY: &str = "proxy-capacity";

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Full {
    /// Every slot is taken.
    Slots,
    /// The connections not yet authenticated hold their share.
    Pending,
}

impl Full {
    const ALL: [Self; 2] = [Self::Slots, Self::Pending];

    /// What the 503 says.
    pub(super) fn reply(self) -> &'static str {
        match self {
            Self::Slots => "too many connections",
            Self::Pending => "too many connections waiting to authenticate",
        }
    }
}

/// The refusals at accept of one [`Proxy::serve`](crate::Proxy::serve).
#[derive(Debug, Default)]
pub(super) struct Refusals {
    counts: Coalesce<2>,
}

impl Refusals {
    /// Count one refusal, and record the count once [`INTERVAL`] has passed
    /// since the last row of its kind.
    pub(super) fn refused(&self, full: Full, recorder: &dyn Recorder, now: Instant) {
        if let Some(count) = self.counts.refused(full as usize, now) {
            write(full, count, recorder);
        }
    }

    /// Record the refusals counted since the last row, where [`INTERVAL`] has
    /// passed: called as connections are accepted, so a burst that ends is
    /// still recorded.
    pub(super) fn flush(&self, recorder: &dyn Recorder, now: Instant) {
        for (kind, count) in self.counts.due(now) {
            if let Some(full) = Full::ALL.get(kind) {
                write(*full, count, recorder);
            }
        }
    }
}

fn write(full: Full, count: u64, recorder: &dyn Recorder) {
    let decision = Decision::single(
        Verdict::Deny,
        RULE_CAPACITY,
        format!(
            "{} refused before a request was read: {}; later ones within {} s are counted in \
             the next row",
            counted(count, "connection", "connections"),
            full.reply(),
            INTERVAL.as_secs()
        ),
    );
    let connection = Connection {
        session: None,
        method: None,
        destination: None,
        terminated: false,
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
