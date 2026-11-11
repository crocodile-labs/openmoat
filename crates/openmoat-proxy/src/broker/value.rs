//! A brokered secret's value as it changes while the proxy runs (ADR-087).
//!
//! A value read once (an `env`, `file` or `keychain` source) never expires. A
//! value from a `command` source has a deadline: past it the value is not put
//! into any request, and the request is refused ([`super::RULE_SECRET_EXPIRED`]).
//! The deadline is kept on two clocks and is past when either says so: the
//! monotonic clock does not count a machine's sleep on every system, and the
//! wall clock can be set back.
//!
//! The values a slot held before stay known to the leak and echo checks: a
//! replaced value may still be accepted by its server until its own expiry.

use std::collections::VecDeque;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use super::BrokerError;

/// How many replaced values each slot keeps for the leak and echo checks.
const KEPT: usize = 4;

/// The current value, its deadline and the values it replaced.
pub(super) struct Slot {
    current: Zeroizing<String>,
    until: Option<(Instant, SystemTime)>,
    replaced: VecDeque<Zeroizing<String>>,
}

impl Slot {
    pub(super) fn fixed(value: Zeroizing<String>) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            current: value,
            until: None,
            replaced: VecDeque::new(),
        }))
    }

    /// The value to put into a request now, `None` past its deadline.
    pub(super) fn live(&self) -> Option<&Zeroizing<String>> {
        match self.until {
            Some((mono, wall)) if Instant::now() >= mono || SystemTime::now() >= wall => None,
            _ => Some(&self.current),
        }
    }

    /// Every value the leak and echo checks look for: the current one, live or
    /// not, and those it replaced.
    pub(super) fn known(&self) -> impl Iterator<Item = &Zeroizing<String>> {
        std::iter::once(&self.current).chain(&self.replaced)
    }
}

/// Read `slot`; a writer that panicked left a whole value or the one before.
pub(super) fn read(slot: &RwLock<Slot>) -> RwLockReadGuard<'_, Slot> {
    slot.read().unwrap_or_else(PoisonError::into_inner)
}

/// The handle that renews one secret's value ([`super::Broker::rotation`]).
/// `Debug` names the secret only.
#[derive(Clone)]
pub struct Rotation {
    id: String,
    slot: Arc<RwLock<Slot>>,
}

impl std::fmt::Debug for Rotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rotation")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Rotation {
    pub(super) fn new(id: &str, slot: &Arc<RwLock<Slot>>) -> Self {
        Self {
            id: id.to_owned(),
            slot: Arc::clone(slot),
        }
    }

    /// Use `value` for the next `lifetime`, and from then on never again unless
    /// renewed. The value it replaces stays known to the leak and echo checks.
    /// Refused, and the slot left as it was, for a value the broker cannot use.
    pub fn renew(&self, value: Zeroizing<String>, lifetime: Duration) -> Result<(), BrokerError> {
        super::usable(&self.id, &value)?;
        let until = (
            Instant::now() + lifetime,
            SystemTime::now()
                .checked_add(lifetime)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        );
        let mut slot = self.slot.write().unwrap_or_else(PoisonError::into_inner);
        if *slot.current != *value {
            let old = std::mem::replace(&mut slot.current, value);
            slot.replaced.push_front(old);
            slot.replaced.truncate(KEPT);
        }
        slot.until = Some(until);
        Ok(())
    }

    /// How long the current value stays usable: zero once past its deadline
    /// on either clock, `None` for a value that never expires.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        let slot = read(&self.slot);
        let (mono, wall) = slot.until?;
        let by_wall = wall
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        Some(mono.saturating_duration_since(Instant::now()).min(by_wall))
    }
}

#[cfg(test)]
mod tests;
