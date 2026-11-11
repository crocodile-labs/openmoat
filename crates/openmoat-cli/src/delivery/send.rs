//! One request to one sink: the body in its format, its headers, the answer
//! read as accepted, worth trying again, or not (ADR-081).

use std::time::Duration;

use anyhow::{Context as _, Result};
use openmoat_audit::EventId;
use openmoat_audit::delivery::{self, Delivered, Gap, Origin};
use openmoat_proxy::{Poster, Roots, SystemResolver};
use zeroize::Zeroizing;

use super::config::{Kind, Sink};
use super::sign;

/// Each step of a request (connect, write, read) gets this long.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// A sink ready to send to: its client and the values it sends with, read
/// once per run. `Debug` names no value.
pub struct Ready {
    poster: Poster,
    key: Option<Zeroizing<String>>,
    headers: Vec<(String, Zeroizing<String>)>,
}

impl std::fmt::Debug for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ready").finish_non_exhaustive()
    }
}

/// How a request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    Accepted,
    /// Try again later; the sink may have said when.
    Retry {
        why: String,
        retry_after_s: Option<u64>,
    },
    /// `413`: the request is too large for the sink. Fewer events may pass;
    /// one event alone that gets it is skipped, never a reason to pause.
    TooLarge,
    /// An answer that trying again cannot change.
    Refused {
        why: String,
    },
}

/// The status a sink answers a request too large for it with.
const TOO_LARGE: u16 = 413;

impl Ready {
    /// Read the sink's key, header values and CA. `home` is the user's home
    /// directory, for the error messages of `~/` paths.
    pub fn new(sink: &Sink, home: &str) -> Result<Self> {
        let roots = match &sink.ca_file {
            Some(path) => Roots::Pem(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?,
            ),
            None => Roots::System,
        };
        let poster = Poster::new(&roots, Box::new(SystemResolver))?;
        let key = sink
            .secret
            .as_ref()
            .map(|source| crate::secrets::read(source, home).context("reading the webhook key"))
            .transpose()?;
        let mut headers = Vec::new();
        for header in &sink.headers {
            let value = crate::secrets::read(&header.value, home)
                .with_context(|| format!("reading the value of header {}", header.name))?;
            let mut full = Zeroizing::new(header.prefix.clone());
            full.push_str(&value);
            headers.push((header.name.clone(), full));
        }
        Ok(Self {
            poster,
            key,
            headers,
        })
    }

    /// The values to mask in what this sink is sent, besides the policy's.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.key
            .iter()
            .map(|k| k.as_str())
            .chain(self.headers.iter().map(|(_, v)| v.as_str()))
    }

    /// Send `records` and `gaps` to `sink` in its format.
    pub fn send(
        &self,
        sink: &Sink,
        origin: Origin<'_>,
        records: &[Delivered],
        gaps: &[Gap],
        now_ms: i64,
    ) -> Result<Sent> {
        let (body, content_type) = match sink.kind {
            Kind::Otlp => (
                delivery::otlp_logs(origin, now_ms, records, gaps)?,
                "application/json",
            ),
            Kind::Webhook => (
                delivery::webhook_body(origin, now_ms, records, gaps)?,
                "application/json",
            ),
        };
        let mut headers: Vec<(&str, String)> = vec![("Content-Type", content_type.to_owned())];
        headers.push(("User-Agent", format!("openmoat/{}", origin.version)));
        if let Some(key) = &self.key {
            headers.push((sign::TIMESTAMP, now_ms.to_string()));
            headers.push((
                sign::SIGNATURE,
                sign::signature(key.as_bytes(), now_ms, &body),
            ));
            headers.push((sign::DELIVERY, batch_name(sink, records, gaps)));
        }
        let mut all: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        all.extend(self.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())));
        Ok(
            match self.poster.post(&sink.endpoint, &all, &body, STEP_TIMEOUT) {
                Ok(answer) if answer.accepted() => Sent::Accepted,
                Ok(answer) if answer.status == TOO_LARGE => Sent::TooLarge,
                Ok(answer) if answer.retryable() => Sent::Retry {
                    why: format!("HTTP {}", answer.status),
                    retry_after_s: answer.retry_after_s,
                },
                Ok(answer) => Sent::Refused {
                    why: format!("HTTP {}", answer.status),
                },
                // Network and TLS failures may pass; a URL or address the
                // client refuses will not.
                Err(
                    e @ (openmoat_proxy::PostError::Address { .. }
                    | openmoat_proxy::PostError::PlainOffMachine { .. }
                    | openmoat_proxy::PostError::Url(_)
                    | openmoat_proxy::PostError::Header(_)),
                ) => Sent::Refused { why: e.to_string() },
                Err(e) => Sent::Retry {
                    why: e.to_string(),
                    retry_after_s: None,
                },
            },
        )
    }
}

/// `<sink>-<first id>-<last id>` of the events, or of the gaps when there are
/// none: the same for every retry of a batch.
fn batch_name(sink: &Sink, records: &[Delivered], gaps: &[Gap]) -> String {
    let ids: Vec<EventId> = records
        .iter()
        .map(|r| r.id)
        .chain(gaps.iter().flat_map(|g| [g.first, g.last]))
        .collect();
    let first = ids.iter().map(|id| id.0).min().unwrap_or(0);
    let last = ids.iter().map(|id| id.0).max().unwrap_or(0);
    format!("{}-{:x}-{:x}", sink.id, first, last)
}
