//! A brokered value coming back (ADR-043): the answer to a request the value
//! went into is read before it reaches the agent, and stopped where it holds
//! a value. A server that echoes the request (a debugging endpoint, an error
//! page quoting a header) would otherwise hand the agent what the broker
//! keeps from it.
//!
//! The answer is released as it arrives, less its last bytes: as many as the
//! longest value has, minus one. Whatever is released has been searched
//! together with what came before it, so no released byte starts a whole
//! value; a value split across reads is caught when its last part arrives.
//! Matching is on exact bytes, like the leak check: a value the server
//! encodes (base64, JSON escapes, compression, which the proxy turns off by
//! asking for `identity`) is not recognised (`docs/THREAT_MODEL.md`).

use zeroize::Zeroizing;

use super::{Broker, contains};

impl Broker {
    /// The id of the first brokered secret whose value occurs in `bytes`.
    pub(crate) fn value_in(&self, bytes: &[u8]) -> Option<&str> {
        self.held
            .iter()
            .find(|h| contains(bytes, h.value.as_bytes()))
            .map(|h| h.secret.id.as_str())
    }
}

/// Holds back the end of a stream until it is known not to start a value.
pub(crate) struct Holdback<'a> {
    broker: &'a Broker,
    keep: usize,
    /// Searched but not released yet. It may hold part of a value: zeroed.
    pending: Zeroizing<Vec<u8>>,
}

impl<'a> Holdback<'a> {
    pub(crate) fn new(broker: &'a Broker) -> Self {
        let keep = broker
            .held
            .iter()
            .map(|h| h.value.len())
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        Self {
            broker,
            keep,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// Take the next `data`; the bytes now safe to release, or the id of the
    /// secret whose value the stream holds.
    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'a str> {
        self.pending.extend_from_slice(data);
        if let Some(id) = self.broker.value_in(&self.pending) {
            return Err(id);
        }
        let release = self.pending.len().saturating_sub(self.keep);
        let rest = Zeroizing::new(self.pending[release..].to_vec());
        self.pending.truncate(release);
        Ok(std::mem::replace(&mut self.pending, rest))
    }

    /// The stream ended: what is still held, already searched.
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.pending
    }
}
