//! Bounds on what one client can make the proxy hold.

use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

/// Bounds on what one client can make the proxy hold.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest request head, in bytes.
    pub max_head_bytes: usize,
    /// Time allowed for the request head, and for the `ClientHello` after it.
    pub handshake_timeout: Duration,
    /// A relayed connection with no bytes either way for this long is closed.
    pub idle_timeout: Duration,
    /// Time allowed to connect to the destination.
    pub connect_timeout: Duration,
    /// Connections served at once; more are answered 503 and closed. With
    /// sessions, one session (or the connections not yet authenticated) may
    /// hold at most half of them.
    pub max_connections: usize,
}

impl Limits {
    /// Refuse limits under which no connection could be served: a zero limit,
    /// or a timeout too large to set a deadline with.
    pub(super) fn check(&self) -> io::Result<()> {
        let now = Instant::now();
        let sizes = [
            ("max_head_bytes", self.max_head_bytes),
            ("max_connections", self.max_connections),
        ];
        let timeouts = [
            ("handshake_timeout", self.handshake_timeout),
            ("idle_timeout", self.idle_timeout),
            ("connect_timeout", self.connect_timeout),
        ];
        let bad = sizes
            .iter()
            .find(|(_, n)| *n == 0)
            .map(|(name, _)| name)
            .or_else(|| {
                timeouts
                    .iter()
                    .find(|(_, d)| d.is_zero() || now.checked_add(*d).is_none())
                    .map(|(name, _)| name)
            });
        match bad {
            Some(name) => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("proxy limit `{name}` is zero or too large"),
            )),
            None => Ok(()),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 16 * 1024,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(2),
            connect_timeout: Duration::from_secs(10),
            max_connections: 256,
        }
    }
}
