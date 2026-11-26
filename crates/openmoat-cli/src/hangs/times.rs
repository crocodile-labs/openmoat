//! How long the guard has spent in each phase of its call so far (ADR-130):
//! each [`super::enter`] closes the phase before it, and [`spent`] closes the
//! current one up to now, so the audit row carries the times up to the moment
//! it is written. A phase entered more than once (`record`, around `cache`)
//! adds up. Durations only, by the phase's fixed name.

use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use super::{PHASES, Phase};

/// The phases' times, in microseconds, by index into [`PHASES`]; `None` for
/// a phase the call has not been in.
#[derive(Debug)]
pub(super) struct Clock {
    /// The phase the call is in, and since when.
    current: Option<(usize, Instant)>,
    spent_us: [Option<u64>; PHASES.len()],
}

impl Clock {
    pub(super) const fn new() -> Self {
        Self {
            current: None,
            spent_us: [None; PHASES.len()],
        }
    }

    /// The call moves on to the phase at `index` at `now`.
    pub(super) fn enter(&mut self, index: usize, now: Instant) {
        self.close(now);
        self.current = Some((index, now));
    }

    /// Add the time since the current phase's start to it, which goes on
    /// from `now`.
    fn close(&mut self, now: Instant) {
        let Some((index, since)) = self.current else {
            return;
        };
        let us =
            u64::try_from(now.saturating_duration_since(since).as_micros()).unwrap_or(u64::MAX);
        if let Some(slot) = self.spent_us.get_mut(index) {
            *slot = Some(slot.unwrap_or(0).saturating_add(us));
        }
        self.current = Some((index, now));
    }

    /// Every phase the call has been in up to `now`, in [`PHASES`] order.
    pub(super) fn spent(&mut self, now: Instant) -> Vec<(&'static str, u64)> {
        self.close(now);
        PHASES
            .iter()
            .zip(self.spent_us)
            .filter_map(|(phase, us)| Some((phase.name(), us?)))
            .collect()
    }
}

/// The one guard's clock in this process.
static CLOCK: Mutex<Clock> = Mutex::new(Clock::new());

/// The clock moves on to `phase`.
pub(super) fn entered(phase: Phase) {
    let index = PHASES.iter().position(|p| *p == phase).unwrap_or(0);
    let now = Instant::now();
    CLOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .enter(index, now);
}

/// The microseconds this process's guard spent in each phase it has been in,
/// up to now, by phase name.
pub fn spent() -> Vec<(&'static str, u64)> {
    let now = Instant::now();
    CLOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .spent(now)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn index(phase: Phase) -> usize {
        PHASES.iter().position(|p| *p == phase).unwrap()
    }

    #[test]
    fn each_phase_gets_the_time_until_the_next_one_and_reentries_add_up() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut clock = Clock::new();
        assert_eq!(clock.spent(t0), []);
        clock.enter(index(Phase::Stdin), at(0));
        clock.enter(index(Phase::Lock), at(2));
        clock.enter(index(Phase::Record), at(5));
        clock.enter(index(Phase::Cache), at(6));
        clock.enter(index(Phase::Record), at(10));
        // Up to the write: the current phase counts until now.
        let spent = clock.spent(at(13));
        assert_eq!(
            spent,
            [
                ("stdin", 2_000),
                ("lock", 3_000),
                ("cache", 4_000),
                ("record", 4_000)
            ]
        );
        // Asking again goes on from where the last answer stopped.
        assert_eq!(clock.spent(at(14)).last(), Some(&("record", 5_000)));
    }

    #[test]
    fn a_phase_not_entered_is_left_out() {
        let t0 = Instant::now();
        let mut clock = Clock::new();
        clock.enter(index(Phase::Compile), t0);
        let spent = clock.spent(t0 + Duration::from_micros(7));
        assert_eq!(spent, [("compile", 7)]);
    }
}
