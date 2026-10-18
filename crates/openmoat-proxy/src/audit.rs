//! One record per connection decision.
//!
//! As with `moat guard`, the record is part of the decision: a connection that
//! cannot be recorded is not made. The CLI records into the moat audit log;
//! this crate stays free of storage.

use openmoat_core::Decision;

/// One connection decision.
#[derive(Debug, Clone, Copy)]
pub struct Connection<'a> {
    /// The session whose credential the request carried (ADR-027). `None` for
    /// a proxy without sessions, and for a request refused for its credential;
    /// the recorder then uses its own session.
    pub session: Option<&'a str>,
    /// Request method (`CONNECT`, `GET`, …); `None` when the head was unreadable.
    pub method: Option<&'a str>,
    /// Destination host and port; `None` when the head was unreadable.
    pub destination: Option<(&'a str, u16)>,
    /// The verdict and the rules behind it.
    pub decision: &'a Decision,
    /// Time from accepting the connection to this decision, in microseconds.
    pub latency_us: u64,
}

/// Where connection decisions go. An error refuses the connection.
pub trait Recorder: Send + Sync {
    /// Record one decision.
    fn record(&self, connection: &Connection<'_>) -> Result<(), RecordError>;

    /// Told when [`record`](Self::record) failed. The connection is refused
    /// either way; this is where the failure is reported, somewhere other than
    /// the audit log that just failed. The default does nothing.
    fn unrecorded(&self, error: &RecordError) {
        let _ = error;
    }
}

/// A decision could not be recorded.
#[derive(Debug, thiserror::Error)]
#[error("audit log unavailable: {0}")]
pub struct RecordError(pub String);
