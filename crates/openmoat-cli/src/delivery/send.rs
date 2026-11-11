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
    /// Every form of the header values an event could hold ([`masked`]).
    masked: Vec<Zeroizing<String>>,
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
    /// An OTLP collector accepted the request without some of its records,
    /// which it says must not be sent again.
    Partial(delivery::Rejected),
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
        let mut forms = Vec::new();
        for header in &sink.headers {
            let value = crate::secrets::read(&header.value, home)
                .with_context(|| format!("reading the value of header {}", header.name))?;
            forms.extend(masked(&header.prefix, &value));
            let mut full = Zeroizing::new(header.prefix.clone());
            full.push_str(&value);
            headers.push((header.name.clone(), full));
        }
        Ok(Self {
            poster,
            key,
            headers,
            masked: forms,
        })
    }

    /// The values to mask in what this sink is sent, besides the policy's:
    /// the key, and each header value in every form an event could hold it
    /// ([`masked`]).
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.key.iter().chain(&self.masked).map(|v| v.as_str())
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
                Ok(answer) if answer.accepted() => accepted(sink.kind, answer.body.as_deref()),
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

/// The forms of a header's secret `value` sent after `prefix` that an event
/// could hold, to be masked: the header value as sent (`Bearer <token>`),
/// the bare value (an agent's `curl -H "Authorization: Bearer $TOKEN"`
/// records only `$TOKEN` expanded), the value with its spaces trimmed, and
/// for `Basic` credentials what the base64 says, `user:password`, and the
/// password alone. [`KnownSecrets`](openmoat_audit::KnownSecrets) leaves
/// out any form too short to mask safely.
fn masked(prefix: &str, value: &str) -> Vec<Zeroizing<String>> {
    let mut forms = vec![
        Zeroizing::new(format!("{prefix}{value}")),
        Zeroizing::new(value.to_owned()),
        Zeroizing::new(value.trim().to_owned()),
    ];
    if prefix.trim().eq_ignore_ascii_case("basic")
        && let Some(decoded) = openmoat_proxy::base64(value.trim().as_bytes())
        && let Ok(pair) = std::str::from_utf8(&decoded)
    {
        if let Some((_, password)) = pair.split_once(':') {
            forms.push(Zeroizing::new(password.to_owned()));
        }
        forms.push(Zeroizing::new(pair.to_owned()));
    }
    forms.retain(|form| !form.is_empty());
    forms
}

/// A success: whole, or, from an OTLP collector whose body names rejected
/// records, partial. A body that was not read whole names none: the status
/// is all there is to go by.
fn accepted(kind: Kind, body: Option<&[u8]>) -> Sent {
    match (kind, body.and_then(delivery::otlp_rejected)) {
        (Kind::Otlp, Some(rejected)) => Sent::Partial(rejected),
        _ => Sent::Accepted,
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

#[cfg(test)]
mod tests {
    use openmoat_audit::KnownSecrets;

    use super::*;
    use crate::home::Home;

    /// A sink's `Authorization: Bearer <token>` header and `Basic`
    /// credentials: an event holding the bare token, the header, the
    /// decoded `user:password` or the password alone is masked, though the
    /// values match no built-in pattern.
    #[test]
    fn every_form_of_a_header_secret_is_masked() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let delivery = home.root().join("delivery");
        std::fs::create_dir_all(&delivery).unwrap();
        // Made at run time, shaped like no known token.
        let token = format!("plain{}words{}", "-and-", 31_337);
        let password = format!("pass{}word{}", "-phrase-", 4_242);
        let basic = encode(format!("someone:{password}").as_bytes());
        std::fs::write(delivery.join("token"), format!("{token}\n")).unwrap();
        std::fs::write(delivery.join("basic"), &basic).unwrap();
        let path = |name: &str| delivery.join(name).to_string_lossy().replace('\\', "/");
        let yaml = format!(
            "version: 1\nmachine: m\nsinks:\n  - id: c\n    otlp: http://127.0.0.1:9/v1/logs\n    \
             headers:\n      - name: Authorization\n        prefix: \"Bearer \"\n        \
             value: {{ file: '{}' }}\n      - name: X-Basic\n        prefix: \"Basic \"\n        \
             value: {{ file: '{}' }}\n",
            path("token"),
            path("basic"),
        );
        let config = super::super::config::parse(&yaml, &home).unwrap();
        let ready = Ready::new(&config.sinks[0], "/home/someone").unwrap();
        let known = KnownSecrets::new(ready.values()).unwrap();
        for text in [
            format!("curl -H \"Authorization: Bearer {token}\" https://x"),
            format!("echo {token} > /tmp/t"),
            format!("echo {}", token.to_uppercase()),
            format!("curl -u someone:{password} https://x"),
            format!("echo {password}"),
            format!("curl -H 'X-Basic: Basic {basic}' https://x"),
        ] {
            let masked = known.redact(&text);
            for secret in [&token, &password, &basic] {
                assert!(
                    !masked.to_lowercase().contains(&secret.to_lowercase()),
                    "{masked}"
                );
            }
        }
    }

    /// Standard base64 with padding, for the test's `Basic` credentials.
    fn encode(raw: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in raw.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
