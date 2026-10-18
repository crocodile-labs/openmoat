//! Shares of the proxy's connections (#555).
//!
//! In session mode no one holder may keep more than half of
//! `max_connections` open: neither one session nor the connections that have
//! not presented a credential yet, which share one holder of their own. A
//! client that opens connections and sends nothing can then take at most half
//! the slots, for at most the handshake timeout, and a session that opens
//! hundreds of tunnels leaves the other half to everyone else.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// The holder of connections that have not authenticated yet. Session ids are
/// never empty (`Credential::new`), so it names no session.
pub(crate) const PENDING: &str = "";

/// Open connections per holder, each capped at half the proxy's slots.
#[derive(Debug)]
pub(crate) struct Shares {
    cap: usize,
    held: Mutex<HashMap<String, usize>>,
}

impl Shares {
    /// Shares of `max_connections` slots: half each, at least one.
    pub(crate) fn new(max_connections: usize) -> Self {
        Self {
            cap: (max_connections / 2).max(1),
            held: Mutex::new(HashMap::new()),
        }
    }

    /// The most connections one holder may keep open.
    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    /// One more connection for `holder`, released when dropped; `None` when it
    /// already holds its share.
    pub(crate) fn take(&self, holder: &str) -> Option<Share<'_>> {
        // A counter is consistent even after a panic elsewhere; recover it.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(holder.to_owned()).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(Share {
            shares: self,
            holder: holder.to_owned(),
        })
    }

    #[cfg(test)]
    fn held(&self, holder: &str) -> usize {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.get(holder).copied().unwrap_or(0)
    }
}

/// One connection of a holder's share.
#[derive(Debug)]
pub(crate) struct Share<'a> {
    shares: &'a Shares,
    holder: String,
}

impl Drop for Share<'_> {
    fn drop(&mut self) {
        let mut held = self
            .shares
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.holder) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.holder);
            }
        }
    }
}

#[cfg(test)]
mod tests;
