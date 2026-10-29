//! One request inside a terminated tunnel (ADR-043).
//!
//! Order: finish the agent's TLS handshake with the host's leaf → read one
//! request head (`request::origin`) → refuse a brokered secret bound
//! elsewhere (the leak check) → refuse a request the host's secrets' `allow`
//! rules do not name → (session mode) the session's taint → connect and
//! verify the upstream → record → put the value in → forward the body,
//! watched like a plain-HTTP body → relay the answer, stopped where it holds
//! a value (`response.rs`) → close.
//!
//! Nothing reaches the upstream before the request is checked and recorded,
//! and a refused request never opens a connection to it. One request per
//! tunnel: the head sent upstream says `Connection: close`, and whatever the
//! agent sends after the request's body is never read, so a second request
//! (for another host, or after the rules were checked) cannot follow it. The
//! proxy reads one direction at a time: the whole request, then the answer.

mod response;

use std::cell::Cell;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use openmoat_core::{Decision, Verdict};
use rustls::{ServerConnection, StreamOwned};
use zeroize::Zeroizing;

use crate::body::BodyEnd;
use crate::broker::{Broker, Channel, Watch};
use crate::decide::RULE_REQUEST;
use crate::request::origin::{self, Inner};
use crate::server::{Limits, response as answer};
use crate::tls::{RULE_TLS, Tls};

const BUFFER: usize = 16 * 1024;

/// A connection the proxy reads and writes with timeouts: TCP, or a socket
/// pair in tests.
pub(crate) trait Wire: Read + Write {
    /// Set both timeouts; an error closes the connection.
    fn timeouts(&self, read: Duration, write: Duration) -> io::Result<()>;
    /// Close both directions.
    fn close(&self);
}

impl Wire for &TcpStream {
    fn timeouts(&self, read: Duration, write: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(read))?;
        self.set_write_timeout(Some(write))
    }

    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

impl Wire for TcpStream {
    fn timeouts(&self, read: Duration, write: Duration) -> io::Result<()> {
        <&TcpStream as Wire>::timeouts(&self, read, write)
    }

    fn close(&self) {
        <&TcpStream as Wire>::close(&self);
    }
}

/// Records one decision about the tunnel, with the method of the request it
/// is about (`None` when no request was read); `false` when it could not be
/// recorded, which refuses the request.
pub(crate) type Record<'a> = &'a dyn Fn(Option<&str>, &Decision) -> bool;

/// What one terminated tunnel to `host` needs from the proxy.
pub(crate) struct Tunnel<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) broker: &'a Broker,
    pub(crate) tls: &'a Tls,
    pub(crate) limits: &'a Limits,
    /// The host's allow decision, which each request's row repeats.
    pub(crate) allowed: &'a Decision,
    pub(crate) record: Record<'a>,
    /// `false` once the session's taint refuses the host (recorded by it).
    pub(crate) still_allowed: &'a dyn Fn() -> bool,
}

/// Why the tunnel ends early. The decision, if any, is still to be recorded.
enum Stop {
    /// Recorded already, or nothing to record (the agent left).
    Quiet,
    /// Record this and answer the agent with the status.
    Refuse(u16, Decision),
    /// Record this; the agent gets no answer (one is already under way).
    Cut(Decision),
}

impl Tunnel<'_> {
    /// Serve the tunnel `client` opened, whose `ClientHello` (`hello`) the
    /// proxy already read and checked. `connect` opens the TCP connection to
    /// the upstream, or says why not.
    pub(crate) fn serve<C: Wire, U: Wire>(
        &self,
        client: C,
        hello: &[u8],
        connect: &mut dyn FnMut() -> Result<U, (u16, Decision)>,
    ) {
        let handshake = self.limits.handshake_timeout;
        let deny = |why: String| Decision::single(Verdict::Deny, RULE_TLS, why);
        if client.timeouts(handshake, handshake).is_err() {
            client.close();
            return;
        }
        let conn = match self.tls.accept(self.host) {
            Ok(conn) => conn,
            Err(e) => {
                (self.record)(Some("CONNECT"), &deny(e.to_string()));
                client.close();
                return;
            }
        };
        let mut agent = StreamOwned::new(conn, client);
        if let Err(why) = accept(&mut agent, hello) {
            (self.record)(Some("CONNECT"), &deny(self.client_failure(&why)));
            agent.sock.close();
            return;
        }
        let mut method = None;
        match self.exchange(&mut agent, &mut method, connect) {
            Ok(()) => {}
            Err(Stop::Refuse(status, decision)) => {
                (self.record)(method.as_deref(), &decision);
                let text = format!(
                    "{} ({})",
                    decision.reasons.join("; "),
                    decision.rules.join(", ")
                );
                let _ = agent.write_all(answer(status, &text).as_bytes());
            }
            // Closed without `close_notify`: the agent sees a cut tunnel, not
            // an answer that ended.
            Err(Stop::Quiet) => {
                agent.sock.close();
                return;
            }
            Err(Stop::Cut(decision)) => {
                (self.record)(method.as_deref(), &decision);
                agent.sock.close();
                return;
            }
        }
        agent.conn.send_close_notify();
        let _ = agent.flush();
        agent.sock.close();
    }

    /// Read, check, forward and answer one request. `method` is set once its
    /// head is read, for the rows recorded after.
    fn exchange<C: Wire, U: Wire>(
        &self,
        agent: &mut StreamOwned<ServerConnection, C>,
        method: &mut Option<String>,
        connect: &mut dyn FnMut() -> Result<U, (u16, Decision)>,
    ) -> Result<(), Stop> {
        let mut buf = Zeroizing::new(Vec::new());
        let inner = self.read_head(agent, &mut buf)?;
        *method = Some(inner.method.clone());
        // From here on a read waits for the body or the answer, not the handshake.
        if agent
            .sock
            .timeouts(self.pace().wait(), self.limits.idle_timeout)
            .is_err()
        {
            return Err(Stop::Quiet);
        }
        let mut watch = Watch::new(self.broker, self.host);
        if let Some(leak) = watch.next(&buf) {
            return Err(Stop::Refuse(403, leak.decision(self.host)));
        }
        let routed = self
            .broker
            .admit(self.host, Channel::Terminated, &inner.head)
            .map_err(|refused| Stop::Refuse(403, refused))?;
        if !(self.still_allowed)() {
            return Err(Stop::Quiet);
        }
        let mut upstream = self.upstream(connect)?;
        let mut row = self.allowed.clone();
        row.reasons.push(format!(
            "{} request read inside a TLS tunnel the proxy terminated",
            inner.method
        ));
        row.reasons.extend(routed);
        if !(self.record)(Some(&inner.method), &row) {
            upstream.sock.close();
            return Err(Stop::Refuse(403, audit_unavailable()));
        }
        let sent = self.forward(agent, &mut upstream, &inner, &buf, &mut watch);
        let answered = sent.and_then(|()| {
            response::relay(
                &mut upstream,
                agent,
                &inner.method,
                self.broker,
                self.host,
                &self.pace(),
            )
        });
        upstream.sock.close();
        answered
    }

    fn read_head<C: Wire>(
        &self,
        agent: &mut StreamOwned<ServerConnection, C>,
        buf: &mut Vec<u8>,
    ) -> Result<Inner, Stop> {
        let deadline = Instant::now() + self.limits.handshake_timeout;
        let malformed =
            |why: String| Stop::Refuse(400, Decision::single(Verdict::Deny, RULE_REQUEST, why));
        let mut chunk = [0u8; 4096];
        loop {
            match origin::parse(buf, self.host, self.port) {
                Ok(Some(inner)) => return Ok(inner),
                Ok(None) if buf.len() >= self.limits.max_head_bytes => {
                    return Err(malformed(format!(
                        "request head larger than {} bytes",
                        self.limits.max_head_bytes
                    )));
                }
                Ok(None) => {}
                Err(e) => return Err(malformed(e.to_string())),
            }
            if Instant::now() >= deadline {
                return Err(malformed(
                    "the client did not send its request in time".to_owned(),
                ));
            }
            match agent.read(&mut chunk) {
                // The agent closed the tunnel without a request: nothing to record.
                Ok(0) => return Err(Stop::Quiet),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if buf.is_empty() && closed(&e) => return Err(Stop::Quiet),
                Err(e) => return Err(malformed(format!("reading the request: {e}"))),
            }
        }
    }

    /// The upstream, connected and verified for the host.
    fn upstream<U: Wire>(
        &self,
        connect: &mut dyn FnMut() -> Result<U, (u16, Decision)>,
    ) -> Result<StreamOwned<rustls::ClientConnection, U>, Stop> {
        let deny = |why: String| Stop::Refuse(502, Decision::single(Verdict::Deny, RULE_TLS, why));
        let sock = connect().map_err(|(status, decision)| Stop::Refuse(status, decision))?;
        let wait = self.limits.connect_timeout;
        let conn = match (sock.timeouts(wait, wait), self.tls.connect(self.host)) {
            (Ok(()), Ok(conn)) => conn,
            (Err(e), _) => {
                sock.close();
                return Err(deny(format!(
                    "setting up the connection to {}: {e}",
                    self.host
                )));
            }
            (_, Err(e)) => {
                sock.close();
                return Err(deny(e.to_string()));
            }
        };
        let mut upstream = StreamOwned::new(conn, sock);
        while upstream.conn.is_handshaking() {
            if let Err(e) = upstream.conn.complete_io(&mut upstream.sock) {
                upstream.sock.close();
                return Err(deny(format!(
                    "the TLS handshake with {} failed: {e}; nothing was sent",
                    self.host
                )));
            }
        }
        let idle = self.limits.idle_timeout;
        if upstream.sock.timeouts(self.pace().wait(), idle).is_err() {
            upstream.sock.close();
            return Err(Stop::Quiet);
        }
        Ok(upstream)
    }

    /// Send the head, with the value in, and the request's body.
    fn forward<C: Wire, U: Wire>(
        &self,
        agent: &mut StreamOwned<ServerConnection, C>,
        upstream: &mut StreamOwned<rustls::ClientConnection, U>,
        inner: &Inner,
        buf: &[u8],
        watch: &mut Watch<'_>,
    ) -> Result<(), Stop> {
        let injected = self
            .broker
            .inject(self.host, Channel::Terminated, &inner.head);
        let head: &[u8] = injected.as_deref().map_or(&inner.head, Vec::as_slice);
        let mut body = BodyEnd::new(inner.framing);
        // The payload without its chunked framing, which could split a value.
        let mut payload = Watch::new(self.broker, self.host);
        let rest = &buf[inner.head_len..];
        // The head was watched with the bytes after it already.
        let n = self.take(&mut body, rest, None, &mut payload)?;
        let first = Zeroizing::new([head, &rest[..n]].concat());
        upstream.write_all(&first).map_err(|_| Stop::Quiet)?;
        drop(injected);
        if inner.expects_continue && !body.done() {
            agent
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .map_err(|_| Stop::Quiet)?;
            agent.flush().map_err(|_| Stop::Quiet)?;
        }
        let pace = self.pace();
        let mut chunk = Zeroizing::new(vec![0u8; BUFFER]);
        while !body.done() {
            let read = pace.read(agent, &mut chunk).map_err(|_| Stop::Quiet)?;
            if read == 0 {
                return Err(Stop::Quiet);
            }
            let n = self.take(&mut body, &chunk[..read], Some(watch), &mut payload)?;
            upstream.write_all(&chunk[..n]).map_err(|_| Stop::Quiet)?;
        }
        upstream.flush().map_err(|_| Stop::Quiet)
    }

    /// Feed `bytes` of the request body: how many of them belong to it, once
    /// they (`raw`, unless watched already) and the payload they carry were
    /// checked for a brokered secret bound elsewhere.
    fn take(
        &self,
        body: &mut BodyEnd,
        bytes: &[u8],
        raw: Option<&mut Watch<'_>>,
        payload: &mut Watch<'_>,
    ) -> Result<usize, Stop> {
        let mut data = Zeroizing::new(Vec::new());
        let n = body
            .feed_data(bytes, &mut |d| data.extend_from_slice(d))
            .map_err(|_| {
                Stop::Cut(Decision::single(
                    Verdict::Deny,
                    RULE_REQUEST,
                    "malformed chunked request body",
                ))
            })?;
        let leak = raw
            .and_then(|w| w.next(&bytes[..n]))
            .or_else(|| payload.next(&data));
        match leak {
            Some(leak) => Err(Stop::Cut(leak.decision(self.host))),
            None => Ok(n),
        }
    }

    fn pace(&self) -> Pace<'_> {
        Pace {
            idle: self.limits.idle_timeout,
            every: self.limits.taint_recheck,
            still_allowed: self.still_allowed,
            asked: Cell::new(Instant::now()),
        }
    }

    /// Why the agent's handshake failed, and what to do about it.
    fn client_failure(&self, why: &io::Error) -> String {
        let alpn = why
            .get_ref()
            .and_then(|e| e.downcast_ref::<rustls::Error>())
            .is_some_and(|e| matches!(e, rustls::Error::NoApplicationProtocol));
        if alpn {
            format!(
                "the client offered no `http/1.1` for {} (HTTP/2 alone), which a terminated \
                 tunnel does not read",
                self.host
            )
        } else {
            format!(
                "the TLS handshake with the client for {} failed: {why}; a client must trust the \
                 OpenMoat proxy CA, which `openmoat run` gives it, and one that pins the host's \
                 own certificate cannot use `tls: terminate`",
                self.host
            )
        }
    }
}

/// Finish the agent's handshake, starting from the `ClientHello` already read.
fn accept<C: Wire>(
    agent: &mut StreamOwned<ServerConnection, C>,
    mut hello: &[u8],
) -> io::Result<()> {
    while !hello.is_empty() {
        if agent.conn.read_tls(&mut hello)? == 0 {
            break;
        }
        if let Err(e) = agent.conn.process_new_packets() {
            // The alert rustls queued tells the agent why.
            let _ = agent.conn.write_tls(&mut agent.sock);
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }
    }
    while agent.conn.is_handshaking() {
        agent.conn.complete_io(&mut agent.sock)?;
    }
    Ok(())
}

fn audit_unavailable() -> Decision {
    Decision::single(
        Verdict::Deny,
        crate::decide::RULE_AUDIT,
        "audit log unavailable",
    )
}

/// Whether `e` says the peer went away.
fn closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
    )
}

/// Reads that wait at most the idle timeout, and ask the session's taint at
/// most every `every`, whether bytes flow or not.
struct Pace<'a> {
    idle: Duration,
    every: Duration,
    still_allowed: &'a dyn Fn() -> bool,
    asked: Cell<Instant>,
}

impl Pace<'_> {
    /// The read timeout the sockets get: the shorter of the two.
    fn wait(&self) -> Duration {
        self.idle.min(self.every)
    }

    /// One read into `buf`; `Ok(0)` at the end of the stream, `Err` when it
    /// waited `idle` for nothing, failed, or the taint refuses the host now.
    fn read(&self, from: &mut impl Read, buf: &mut [u8]) -> Result<usize, io::Error> {
        let started = Instant::now();
        loop {
            let read = from.read(buf);
            if self.asked.get().elapsed() >= self.every {
                if !(self.still_allowed)() {
                    return Err(io::Error::other("the session's taint refuses the host now"));
                }
                self.asked.set(Instant::now());
            }
            match read {
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                        && started.elapsed() < self.idle => {}
                other => return other,
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
