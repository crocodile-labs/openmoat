//! The secrets broker (ADR-020): values the proxy holds for the policy's
//! `secrets:` list, and where they may go.
//!
//! A brokered secret's placeholder and value may be sent to its own host only.
//! A plain-HTTP request to that host gets the value in the secret's header
//! ([`Broker::inject`]); the agent never needs it. Any other request that carries either, in its head or its plain-HTTP body,
//! is refused and recorded. The check matches exact bytes: it catches a token
//! sent by mistake or by a naive script, not one that was encoded or split
//! across requests (`docs/THREAT_MODEL.md`). What keeps a secret safe is that
//! the agent never holds the value.
//!
//! Values are zeroed when dropped and never formatted: [`Debug`] and every
//! reason this module writes name the secret's id and host only.

use openmoat_core::{Decision, Secret, Verdict};
use zeroize::Zeroizing;

/// Rule id for a request refused because it carries a brokered secret to a
/// host that is not the secret's own.
pub const RULE_SECRET: &str = "proxy-secret";

/// One secret and its value.
struct Held {
    secret: Secret,
    placeholder: String,
    value: Zeroizing<String>,
}

/// The brokered secrets of one proxy run. [`Broker::default`] holds none.
#[derive(Default)]
pub struct Broker {
    held: Vec<Held>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.held.iter().map(|h| (&h.secret.id, &h.secret.host)))
            .finish()
    }
}

/// A secret value the broker cannot use.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrokerError {
    /// The value is empty.
    #[error("secret `{0}` is empty")]
    Empty(String),
    /// The value holds a control character, which could end the header it is
    /// put in and start another.
    #[error("secret `{0}` contains a control character")]
    Control(String),
}

/// Which form of a secret a request carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
    /// The placeholder the agent holds.
    Placeholder,
    /// The value itself.
    Value,
}

/// A brokered secret found in a request to another host.
#[derive(Debug, Clone, Copy)]
pub struct Leak<'a> {
    /// The secret's id.
    pub id: &'a str,
    /// The only host that may receive it.
    pub owner: &'a str,
    /// Placeholder or value.
    pub carried: Carried,
}

impl Leak<'_> {
    /// The deny recorded for a request to `host` that carried this secret.
    #[must_use]
    pub fn decision(&self, host: &str) -> Decision {
        let what = match self.carried {
            Carried::Placeholder => "placeholder",
            Carried::Value => "value",
        };
        Decision::single(
            Verdict::Deny,
            RULE_SECRET,
            format!(
                "request to {host} carries the {what} of secret `{}`, which only {} may receive",
                self.id, self.owner
            ),
        )
    }
}

impl Broker {
    /// A broker for `secrets`, each with its value. The policy has already
    /// validated the entries; this checks the values.
    pub fn new(secrets: Vec<(Secret, Zeroizing<String>)>) -> Result<Self, BrokerError> {
        let mut held = Vec::with_capacity(secrets.len());
        for (secret, value) in secrets {
            if value.is_empty() {
                return Err(BrokerError::Empty(secret.id));
            }
            if value.chars().any(char::is_control) {
                return Err(BrokerError::Control(secret.id));
            }
            held.push(Held {
                placeholder: secret.placeholder(),
                secret,
                value,
            });
        }
        Ok(Self { held })
    }

    /// True when no secret is brokered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The first secret whose placeholder or value occurs in `bytes`, sent
    /// towards `host`, that `host` may not receive.
    #[must_use]
    pub fn leak(&self, host: &str, bytes: &[u8]) -> Option<Leak<'_>> {
        self.held
            .iter()
            .filter(|h| h.secret.host != host)
            .find_map(|h| {
                let carried = if contains(bytes, h.placeholder.as_bytes()) {
                    Carried::Placeholder
                } else if contains(bytes, h.value.as_bytes()) {
                    Carried::Value
                } else {
                    return None;
                };
                Some(Leak {
                    id: &h.secret.id,
                    owner: &h.secret.host,
                    carried,
                })
            })
    }

    /// Ids of the secrets `host` owns that are not put into plain-HTTP
    /// requests, because their policy entry does not set `plain_http`.
    pub(crate) fn withheld(&self, host: &str) -> Vec<&str> {
        self.held
            .iter()
            .filter(|h| h.secret.host == host && !h.secret.plain_http)
            .map(|h| h.secret.id.as_str())
            .collect()
    }

    /// `head` (a plain-HTTP request head the proxy wrote, lines ending in
    /// CRLF) with the secrets of `host` that allow `plain_http` put in: in
    /// each header a secret names, the placeholder becomes the value; a secret
    /// whose header is absent, or holds no placeholder, gets its own header
    /// line. `None` when there is no such secret.
    pub(crate) fn inject(&self, host: &str, head: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let owned: Vec<&Held> = self
            .held
            .iter()
            .filter(|h| h.secret.host == host && h.secret.plain_http)
            .collect();
        // Each line keeps its `\r`; only the `\n`s are split on and re-added.
        let lines = head.strip_suffix(b"\n\r\n")?;
        if owned.is_empty() {
            return None;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(head.len() + 256));
        let mut placed = vec![false; owned.len()];
        // The first line is the request line; the rest are `Name: value`.
        for (n, line) in lines.split(|b| *b == b'\n').enumerate() {
            let named = header_name(line).filter(|_| n > 0).and_then(|name| {
                owned
                    .iter()
                    .position(|h| name.eq_ignore_ascii_case(h.secret.header.as_bytes()))
            });
            match named {
                None => out.extend_from_slice(line),
                Some(i) if contains(line, owned[i].placeholder.as_bytes()) => {
                    placed[i] = true;
                    let h = owned[i];
                    replace(line, h.placeholder.as_bytes(), h.value.as_bytes(), &mut out);
                }
                // A value the client chose would reach the owner in place of
                // the secret: it is dropped, and the secret's line added below.
                Some(_) => continue,
            }
            out.extend_from_slice(b"\n");
        }
        for (h, _) in owned.iter().zip(&placed).filter(|(_, p)| !**p) {
            out.extend_from_slice(format!("{}: ", h.secret.header).as_bytes());
            out.extend_from_slice(h.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Some(out)
    }

    /// Length of the longest placeholder or value: a stream watched in chunks
    /// keeps one byte less than this from the previous chunk, so a secret
    /// split across two reads is still found.
    fn longest(&self) -> usize {
        self.held
            .iter()
            .map(|h| h.placeholder.len().max(h.value.len()))
            .max()
            .unwrap_or(0)
    }
}

/// Watches one client stream towards `host`, chunk by chunk.
pub(crate) struct Watch<'a> {
    broker: &'a Broker,
    host: &'a str,
    /// The end of the bytes seen so far, kept to find a secret split across
    /// chunks. It may hold part of a value the client sent, so it is zeroed.
    tail: Zeroizing<Vec<u8>>,
}

impl<'a> Watch<'a> {
    pub(crate) fn new(broker: &'a Broker, host: &'a str) -> Self {
        Self {
            broker,
            host,
            tail: Zeroizing::new(Vec::new()),
        }
    }

    /// Look at the next `chunk` of the stream, with the end of the previous one.
    pub(crate) fn next(&mut self, chunk: &[u8]) -> Option<Leak<'a>> {
        if self.broker.is_empty() {
            return None;
        }
        let mut window = Zeroizing::new(Vec::with_capacity(self.tail.len() + chunk.len()));
        window.extend_from_slice(&self.tail);
        window.extend_from_slice(chunk);
        let keep = self.broker.longest().saturating_sub(1).min(window.len());
        self.tail.clear();
        self.tail.extend_from_slice(&window[window.len() - keep..]);
        self.broker.leak(self.host, &window)
    }
}

/// Append `line` to `out` with every `from` replaced by `to`.
fn replace(mut line: &[u8], from: &[u8], to: &[u8], out: &mut Vec<u8>) {
    while let Some(at) = line.windows(from.len()).position(|w| w == from) {
        out.extend_from_slice(&line[..at]);
        out.extend_from_slice(to);
        line = &line[at + from.len()..];
    }
    out.extend_from_slice(line);
}

/// The name of a `Name: value` header line.
fn header_name(line: &[u8]) -> Option<&[u8]> {
    line.iter().position(|b| *b == b':').map(|at| &line[..at])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests;
