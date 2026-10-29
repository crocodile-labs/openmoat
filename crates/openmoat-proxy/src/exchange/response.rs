//! The answer to a terminated request, read before the agent gets it.
//!
//! - The head must be one the proxy can follow: no protocol switch, no
//!   content or transfer coding but `chunked` (the request asked for
//!   `identity`), no conflicting lengths. Its `Connection` headers become
//!   `Connection: close`.
//! - The head and the body are searched for every brokered value; the answer
//!   stops before one (`broker::Holdback`). A chunked body is searched without
//!   its framing and sent on in chunks of the proxy's own, so a value split
//!   by the server's chunking is still found, and an answer cut short is an
//!   incomplete chunked body to the agent, never a shorter whole one.
//! - Interim answers (`100`, `103`) are passed on, up to [`MAX_INTERIM`].

use std::io::{Read, Write};

use openmoat_core::{Decision, Verdict};
use zeroize::Zeroizing;

use super::{BUFFER, Pace, Stop, closed};
use crate::body::{BodyEnd, Framing};
use crate::broker::{Broker, Holdback, RULE_SECRET};
use crate::decide::RULE_UPSTREAM;

/// Largest answer head the proxy reads, and most headers in it.
const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
/// Most interim answers before the final one.
const MAX_INTERIM: usize = 8;

/// Headers about the connection, dropped from the answer: the agent's tunnel
/// ends after it.
const DROPPED: &[&str] = &["connection", "keep-alive", "proxy-connection", "trailer"];

/// One answer head, checked, and rewritten for the agent.
struct Head {
    len: usize,
    interim: bool,
    framing: Framing,
    out: Vec<u8>,
}

/// Relay the answer to a `method` request from `upstream` to `agent`.
pub(super) fn relay<U: Read, C: Write>(
    upstream: &mut U,
    agent: &mut C,
    method: &str,
    broker: &Broker,
    host: &str,
    pace: &Pace<'_>,
) -> Result<(), Stop> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut sent = false;
    // Before the agent got anything it gets a 502 with the reason; after, the
    // tunnel is cut.
    let fail = |sent: bool, rule: &str, why: String| {
        let decision = Decision::single(Verdict::Deny, rule, why);
        if sent {
            Stop::Cut(decision)
        } else {
            Stop::Refuse(502, decision)
        }
    };
    for _ in 0..=MAX_INTERIM {
        let head = match read_head(upstream, &mut buf, method, pace) {
            Ok(head) => head,
            Err(Some(why)) => {
                return Err(fail(
                    sent,
                    RULE_UPSTREAM,
                    format!("the answer from {host}: {why}"),
                ));
            }
            Err(None) => return Err(Stop::Quiet),
        };
        if let Some(id) = broker.value_in(&buf[..head.len]) {
            return Err(fail(sent, RULE_SECRET, echoed(host, id)));
        }
        agent.write_all(&head.out).map_err(|_| Stop::Quiet)?;
        sent = true;
        let rest = Zeroizing::new(buf.split_off(head.len));
        if !head.interim {
            return body(upstream, agent, &rest, head.framing, broker, host, pace);
        }
        buf.clear();
        buf.extend_from_slice(&rest);
    }
    Err(fail(
        sent,
        RULE_UPSTREAM,
        format!("{host} sent more than {MAX_INTERIM} interim answers"),
    ))
}

fn echoed(host: &str, id: &str) -> String {
    format!(
        "the answer from {host} holds the value of secret `{id}`; it was stopped before the value \
         reached the client"
    )
}

/// Read one head into `buf`. `Err(None)`: the upstream went away first.
fn read_head<U: Read>(
    upstream: &mut U,
    buf: &mut Vec<u8>,
    method: &str,
    pace: &Pace<'_>,
) -> Result<Head, Option<String>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head) = parse(buf, method)? {
            return Ok(head);
        }
        if buf.len() >= MAX_HEAD {
            return Err(Some(format!("its head is larger than {MAX_HEAD} bytes")));
        }
        match pace.read(upstream, &mut chunk) {
            Ok(0) | Err(_) => return Err(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The head at the start of `buf`, if complete; `Err` says why it is refused.
fn parse(buf: &[u8], method: &str) -> Result<Option<Head>, Option<String>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let len = match response.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(Some(format!("malformed head ({e})"))),
    };
    let Some(status) = response.code else {
        return Err(Some("no status".to_owned()));
    };
    if status == 101 {
        return Err(Some(
            "it switches protocols, which a terminated tunnel does not relay".to_owned(),
        ));
    }
    let interim = (100..200).contains(&status);
    let mut tokens: Vec<String> = Vec::new();
    for h in response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
    {
        tokens.extend(
            String::from_utf8_lossy(h.value)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase()),
        );
    }
    let mut lengths: Vec<&[u8]> = Vec::new();
    let mut chunked = false;
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
    let mut out = buf[..line_end + 2].to_vec();
    for h in response.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(h.value).to_ascii_lowercase();
        let list: Vec<&str> = value.split(',').map(str::trim).collect();
        match name.as_str() {
            "content-encoding" if list.iter().any(|t| *t != "identity") => {
                return Err(Some(format!(
                    "it is encoded (`{value}`) although `identity` was asked for, so it cannot be \
                     checked for a brokered value"
                )));
            }
            "transfer-encoding" if list != ["chunked"] || chunked => {
                return Err(Some(format!(
                    "its transfer coding `{value}` is not one `chunked`"
                )));
            }
            "transfer-encoding" => chunked = true,
            "content-length" => lengths.push(h.value),
            _ => {}
        }
        if DROPPED.contains(&name.as_str()) || tokens.contains(&name) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    if !interim {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    let framing = framing(status, method, chunked, &lengths)?;
    Ok(Some(Head {
        len,
        interim,
        framing,
        out,
    }))
}

/// How the body ends (RFC 9112 §6.3), refusing framing two readers could
/// read differently.
fn framing(
    status: u16,
    method: &str,
    chunked: bool,
    lengths: &[&[u8]],
) -> Result<Framing, Option<String>> {
    let ambiguous = || {
        Some(
            "its body framing is ambiguous (lengths that differ, or a length with chunked)"
                .to_owned(),
        )
    };
    if (100..200).contains(&status) || status == 204 || status == 304 || method == "HEAD" {
        return Ok(Framing::None);
    }
    if chunked {
        return if lengths.is_empty() {
            Ok(Framing::Chunked)
        } else {
            Err(ambiguous())
        };
    }
    let Some(first) = lengths.first() else {
        return Ok(Framing::UntilClose);
    };
    if lengths.iter().any(|l| l != first) {
        return Err(ambiguous());
    }
    let text = std::str::from_utf8(first)
        .map(str::trim)
        .map_err(|_| ambiguous())?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ambiguous());
    }
    text.parse().map(Framing::Length).map_err(|_| ambiguous())
}

/// Relay the body that starts with `rest`.
fn body<U: Read, C: Write>(
    upstream: &mut U,
    agent: &mut C,
    rest: &[u8],
    framing: Framing,
    broker: &Broker,
    host: &str,
    pace: &Pace<'_>,
) -> Result<(), Stop> {
    let mut relay = Body {
        end: BodyEnd::new(framing),
        hold: Holdback::new(broker),
        chunked: framing == Framing::Chunked,
        host,
    };
    if framing == Framing::None {
        return agent.flush().map_err(|_| Stop::Quiet);
    }
    relay.take(rest, agent)?;
    let mut chunk = Zeroizing::new(vec![0u8; BUFFER]);
    while !relay.end.done() {
        match pace.read(upstream, &mut chunk) {
            Ok(0) => break,
            Ok(n) => relay.take(&chunk[..n], agent)?,
            // Many servers end a body that runs to the close without TLS's
            // `close_notify`.
            Err(e) if framing == Framing::UntilClose && closed(&e) => break,
            Err(_) => return Err(Stop::Quiet),
        }
    }
    if !relay.end.done() && framing != Framing::UntilClose {
        // Cut short: the agent sees an incomplete body, not a complete shorter one.
        return Err(Stop::Quiet);
    }
    let chunked = relay.chunked;
    send(chunked, &relay.hold.finish(), agent)?;
    if chunked {
        agent.write_all(b"0\r\n\r\n").map_err(|_| Stop::Quiet)?;
    }
    agent.flush().map_err(|_| Stop::Quiet)
}

struct Body<'a> {
    end: BodyEnd,
    hold: Holdback<'a>,
    chunked: bool,
    host: &'a str,
}

impl Body<'_> {
    /// Take the next bytes of the body as the upstream framed it.
    fn take(&mut self, bytes: &[u8], agent: &mut impl Write) -> Result<(), Stop> {
        let mut payload = Zeroizing::new(Vec::new());
        self.end
            .feed_data(bytes, &mut |d| payload.extend_from_slice(d))
            .map_err(|_| {
                Stop::Cut(Decision::single(
                    Verdict::Deny,
                    RULE_UPSTREAM,
                    format!("the answer from {}: malformed chunked body", self.host),
                ))
            })?;
        let host = self.host;
        let release = self.hold.push(&payload).map_err(|id| {
            Stop::Cut(Decision::single(
                Verdict::Deny,
                RULE_SECRET,
                echoed(host, id),
            ))
        })?;
        send(self.chunked, &release, agent)
    }
}

/// Send payload bytes on, in a chunk of their own when the agent's head says
/// `chunked`.
fn send(chunked: bool, data: &[u8], agent: &mut impl Write) -> Result<(), Stop> {
    if data.is_empty() {
        return Ok(());
    }
    let sent = if chunked {
        write!(agent, "{:x}\r\n", data.len())
            .and_then(|()| agent.write_all(data))
            .and_then(|()| agent.write_all(b"\r\n"))
    } else {
        agent.write_all(data)
    };
    sent.map_err(|_| Stop::Quiet)
}
