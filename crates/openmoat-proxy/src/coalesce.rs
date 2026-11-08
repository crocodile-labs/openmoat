//! Refusals made before anyone authenticated, recorded at a bounded rate.
//!
//! Any local process may connect: to `openmoat proxy`'s port, and to
//! `openmoat run`'s, which also carries the hook relay. A row for each
//! connection it is refused would let such a process grow the audit log
//! without limit, and a log that can no longer be written makes the proxy and
//! the guard refuse everything. So each kind of refusal is recorded at once
//! the first time, with what it was, and the ones after it are counted and
//! recorded as one row per [`INTERVAL`]: when the next one of the kind comes,
//! when any other connection comes ([`Coalesce::due`]), or when the counter's
//! owner ends. Every refusal is still a refusal; only its row is shared.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The shortest time between two rows of one kind.
pub const INTERVAL: Duration = Duration::from_secs(10);

/// Per kind: when a row was last written, and the refusals not in a row yet.
#[derive(Debug, Default, Clone, Copy)]
struct Kind {
    last: Option<Instant>,
    unrecorded: u64,
}

/// Counters for `N` kinds of refusal, each kind an index below `N`.
#[derive(Debug)]
pub struct Coalesce<const N: usize> {
    kinds: Mutex<[Kind; N]>,
}

impl<const N: usize> Default for Coalesce<N> {
    fn default() -> Self {
        Self {
            kinds: Mutex::new([Kind::default(); N]),
        }
    }
}

impl<const N: usize> Coalesce<N> {
    /// Count one refusal of `kind` at `now`: the number of refusals the row
    /// written now must stand for (this one included), or `None` when a row
    /// of this kind was written less than [`INTERVAL`] ago and this one is
    /// counted in the next. A `kind` of `N` or more is counted as the last.
    pub fn refused(&self, kind: usize, now: Instant) -> Option<u64> {
        let mut kinds = self.kinds.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = kinds.get_mut(kind.min(N.saturating_sub(1)))?;
        slot.unrecorded = slot.unrecorded.saturating_add(1);
        take_due(slot, now)
    }

    /// The counts to record now, by kind, for every kind with refusals not in
    /// a row yet whose last row is at least [`INTERVAL`] old.
    pub fn due(&self, now: Instant) -> Vec<(usize, u64)> {
        let mut kinds = self.kinds.lock().unwrap_or_else(PoisonError::into_inner);
        kinds
            .iter_mut()
            .enumerate()
            .filter(|(_, k)| k.unrecorded > 0)
            .filter_map(|(i, k)| take_due(k, now).map(|n| (i, n)))
            .collect()
    }

    /// Every count not in a row yet, whatever its age: for the owner's end.
    pub fn rest(&self) -> Vec<(usize, u64)> {
        let mut kinds = self.kinds.lock().unwrap_or_else(PoisonError::into_inner);
        kinds
            .iter_mut()
            .enumerate()
            .filter(|(_, k)| k.unrecorded > 0)
            .map(|(i, k)| (i, std::mem::take(&mut k.unrecorded)))
            .collect()
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

/// The words a coalesced row starts with: "1 request", "12 requests".
pub fn counted(count: u64, one: &str, many: &str) -> String {
    let noun = if count == 1 { one } else { many };
    format!("{count} {noun}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_of_a_kind_is_recorded_and_a_flood_is_one_row_per_interval() {
        let counter = Coalesce::<2>::default();
        let start = Instant::now();
        assert_eq!(counter.refused(0, start), Some(1));
        for i in 1..1000u32 {
            let at = start + Duration::from_millis(u64::from(i));
            assert_eq!(counter.refused(0, at), None, "refusal {i}");
        }
        // Another kind has its own first row.
        assert_eq!(counter.refused(1, start), Some(1));
        let later = start + INTERVAL;
        assert_eq!(
            counter.refused(0, later),
            Some(1000),
            "999 counted plus this one"
        );
        assert_eq!(counter.due(later), []);
    }

    #[test]
    fn a_burst_that_ends_is_recorded_by_the_next_connection_or_the_end() {
        let counter = Coalesce::<1>::default();
        let start = Instant::now();
        counter.refused(0, start);
        counter.refused(0, start);
        counter.refused(0, start);
        assert!(counter.due(start).is_empty(), "within the interval");
        assert_eq!(counter.due(start + INTERVAL), [(0, 2)]);
        assert!(counter.due(start + INTERVAL * 3).is_empty(), "nothing left");
        counter.refused(0, start + INTERVAL * 3);
        counter.refused(0, start + INTERVAL * 3);
        assert_eq!(counter.rest(), [(0, 1)]);
        assert_eq!(counter.rest(), []);
    }

    #[test]
    fn rows_are_bounded_by_time_not_by_refusals() {
        let counter = Coalesce::<1>::default();
        let start = Instant::now();
        let mut rows = 0;
        let mut total = 0;
        // 100 000 refusals over one minute: at most one row per interval.
        for i in 0..100_000u64 {
            let at = start + Duration::from_micros(i * 600);
            if let Some(n) = counter.refused(0, at) {
                rows += 1;
                total += n;
            }
        }
        total += counter.rest().iter().map(|(_, n)| n).sum::<u64>();
        assert!(rows <= 7, "{rows} rows");
        assert_eq!(total, 100_000, "every refusal is counted");
    }

    #[test]
    fn words() {
        assert_eq!(counted(1, "request", "requests"), "1 request");
        assert_eq!(counted(3, "request", "requests"), "3 requests");
    }
}
