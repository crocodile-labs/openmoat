//! What leaves the machine when the audit log is delivered live (ADR-081).
//!
//! Each exported event is turned into a [`Delivered`] record with every text
//! the agent could influence redacted once more ([`KnownSecrets::redact`] and
//! its patterns), on top of the redaction the store applied when the row was
//! written: a row an older build stored with fewer patterns is masked by
//! today's before it is sent. The record keeps the event's id and chain hashes,
//! so a row in a SIEM can be matched with `openmoat audit export`, but its
//! cells are no longer the hashed ones: the chain is verified from an export,
//! never from what a collector holds.
//!
//! Two body formats are built from the same records: the generic webhook
//! document ([`webhook_body`]) and OTLP/HTTP logs in JSON ([`otlp_logs`]). Nothing
//! here opens a connection; the CLI sends the bytes.

mod otlp;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventId, ExportedEvent, KnownSecrets, StoreError};

pub use otlp::logs as otlp_logs;

/// The `format` of a webhook body; a new body shape gets a new value.
pub const WEBHOOK_FORMAT: &str = "openmoat-delivery-v1";

/// Where a batch comes from: the machine's name in the person's delivery
/// configuration and the sending build's version.
#[derive(Debug, Clone, Copy)]
pub struct Origin<'a> {
    /// The machine name the configuration gives.
    pub machine: &'a str,
    /// The `openmoat` release that sends.
    pub version: &'a str,
}

/// Events of the log that a sink will never receive, said in the next batch
/// instead of being left out unseen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// First event id skipped.
    pub first: EventId,
    /// Last event id skipped.
    pub last: EventId,
    /// How many events lie between them.
    pub count: u64,
    /// Why they were skipped.
    pub reason: GapReason,
}

/// Why a [`Gap`] was left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GapReason {
    /// The sink fell further behind than its `max_backlog`: the oldest events
    /// beyond it stay in the local log and in `openmoat audit export`.
    BacklogFull,
}

impl Gap {
    /// One line for a person and for the OTLP log body.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.reason {
            GapReason::BacklogFull => format!(
                "{} audit events ({}–{}) were not delivered: the sink fell too far behind; \
                 they are still in the local audit log (`openmoat audit export`)",
                self.count, self.first, self.last
            ),
        }
    }
}

/// One event as it is sent: the export's fields, every text redacted again.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Delivered {
    /// Event id in the sending machine's log (hex).
    pub id: EventId,
    /// Time recorded (ms since the epoch).
    pub ts_ms: i64,
    /// Host id.
    pub host: String,
    /// Host session id.
    pub session_id: String,
    /// Host call id, when sent.
    pub call_id: Option<String>,
    /// Working directory, when sent.
    pub cwd: Option<String>,
    /// Tool name as the host spells it.
    pub tool: String,
    /// The action (`null` for an ungoverned tool).
    pub action: Value,
    /// The verdict.
    pub verdict: String,
    /// Rule ids.
    pub rules: Vec<String>,
    /// Reasons.
    pub reasons: Vec<String>,
    /// Time spent deciding, in microseconds.
    pub latency_us: i64,
    /// The event's chain hash in the sending machine's log.
    pub hash: String,
    /// The chain hash of the event before it.
    pub prev_hash: String,
}

impl Delivered {
    /// `event` with every text redacted by `known` and the patterns. A cell
    /// that does not decode is an error: the batch is not sent rather than
    /// sent with a cell that skipped redaction.
    pub fn of(event: &ExportedEvent, known: &KnownSecrets) -> Result<Self, StoreError> {
        let decode = |reason: String| StoreError::Decode {
            id: event.id,
            reason,
        };
        let json = |raw: &serde_json::value::RawValue| {
            serde_json::from_str::<Value>(raw.get()).map_err(|e| decode(e.to_string()))
        };
        let list = |value: Value| -> Result<Vec<String>, StoreError> {
            serde_json::from_value::<Vec<String>>(known.redact_value(value))
                .map_err(|e| decode(e.to_string()))
        };
        Ok(Self {
            id: event.id,
            ts_ms: event.ts_ms,
            host: known.redact(&event.host),
            session_id: known.redact(&event.session_id),
            call_id: event.call_id.as_deref().map(|c| known.redact(c)),
            cwd: event.cwd.as_deref().map(|c| known.redact(c)),
            tool: known.redact(&event.tool),
            action: known.redact_value(json(&event.action)?),
            verdict: event.verdict.clone(),
            rules: list(json(&event.rules)?)?,
            reasons: list(json(&event.reasons)?)?,
            latency_us: event.latency_us,
            hash: event.hash.clone(),
            prev_hash: event.prev_hash.clone(),
        })
    }
}

/// Records for one request: the first events of `events` whose encoded size
/// stays within `max_bytes`, and always at least one, so a single large event
/// cannot stall the sink.
pub fn pack(
    events: &[ExportedEvent],
    known: &KnownSecrets,
    max_bytes: usize,
) -> Result<Vec<Delivered>, StoreError> {
    let mut packed = Vec::new();
    let mut size = 0usize;
    for event in events {
        let record = Delivered::of(event, known)?;
        let len = serde_json::to_vec(&record)
            .map_err(StoreError::Encode)?
            .len();
        if !packed.is_empty() && size.saturating_add(len) > max_bytes {
            break;
        }
        size = size.saturating_add(len);
        packed.push(record);
    }
    Ok(packed)
}

/// The generic webhook body: `{"format", "machine", "version", "sent_ms",
/// "events", "gaps"}`. The CLI signs these exact bytes.
pub fn webhook_body(
    origin: Origin<'_>,
    sent_ms: i64,
    records: &[Delivered],
    gaps: &[Gap],
) -> Result<Vec<u8>, StoreError> {
    #[derive(Serialize)]
    struct Body<'a> {
        format: &'static str,
        machine: &'a str,
        version: &'a str,
        sent_ms: i64,
        events: &'a [Delivered],
        gaps: &'a [Gap],
    }
    serde_json::to_vec(&Body {
        format: WEBHOOK_FORMAT,
        machine: origin.machine,
        version: origin.version,
        sent_ms,
        events: records,
        gaps,
    })
    .map_err(StoreError::Encode)
}

#[cfg(test)]
mod tests;
