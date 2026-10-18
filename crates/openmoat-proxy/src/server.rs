//! Accepting connections and deciding each one.
//!
//! Order per connection: read the head → check it for brokered secrets bound
//! elsewhere → decide the host → resolve and check the addresses → connect →
//! (CONNECT) answer 200, read the `ClientHello` and check its SNI → record →
//! relay, watching a plain-HTTP body for brokered secrets too. Nothing reaches
//! the destination before the record is written; a failed record closes the
//! connection.

use std::io::{self, ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use openmoat_core::{CompiledPolicy, Decision, Verdict};
use zeroize::Zeroizing;

use crate::audit::{Connection, Recorder};
use crate::body::{self, BodyEnd, Framing};
use crate::broker::{Broker, Watch};
use crate::decide::{self, RULE_REQUEST, RULE_SNI};
use crate::request::{self, Request, Target};
use crate::sni::{self, Hello};
use crate::tunnel::{self, Forward};
use crate::upstream::{self, Refusal, Resolve};

/// Why a request whose chunked body cannot be followed is refused.
const MALFORMED_CHUNKS: &str = "malformed chunked request body";

/// How long, and how much input, a refused connection is drained for.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 1 << 20;

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
    /// Connections served at once; more are answered 503 and closed.
    pub max_connections: usize,
}

impl Limits {
    /// Refuse limits under which no connection could be served: a zero limit,
    /// or a timeout too large to set a deadline with.
    fn check(&self) -> io::Result<()> {
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

/// The proxy: a policy, a resolver, an audit sink and limits.
#[derive(Clone, Copy)]
pub struct Proxy<'a> {
    /// The policy hosts are decided by.
    pub policy: &'a CompiledPolicy<'a>,
    /// Name resolution.
    pub resolver: &'a dyn Resolve,
    /// Where every decision is recorded.
    pub recorder: &'a dyn Recorder,
    /// Resource limits.
    pub limits: &'a Limits,
    /// Brokered secrets; [`Broker::default`] for none.
    pub broker: &'a Broker,
    /// Loopback addresses the proxy may connect to despite the loopback ban.
    /// Empty in `moat proxy`; integration tests list their local server.
    pub loopback_ok: &'a [SocketAddr],
    /// Forward a `ClientHello` that carries an encrypted server name (ECH,
    /// ESNI); refused when false (`sandbox.proxy_allow_ech`).
    pub allow_ech: bool,
}

impl std::fmt::Debug for Proxy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("limits", &self.limits)
            .field("broker", &self.broker)
            .field("loopback_ok", &self.loopback_ok)
            .field("allow_ech", &self.allow_ech)
            .finish_non_exhaustive()
    }
}

impl Proxy<'_> {
    /// Serve connections from `listener` until accepting fails.
    /// Fails at once when the [`Limits`] are zero or too large.
    pub fn serve(&self, listener: &TcpListener) -> io::Result<()> {
        self.limits.check()?;
        let address_policy = decide::address_policy(self.policy.policy());
        let addresses = CompiledPolicy::compile(&address_policy, self.policy.context())
            .map_err(io::Error::other)?;
        let addresses = &addresses;
        let active = AtomicUsize::new(0);
        thread::scope(|scope| {
            loop {
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(e) if is_transient(&e) => continue,
                    Err(e) => return Err(e),
                };
                let _ = client.set_write_timeout(Some(self.limits.handshake_timeout));
                let slot = Slot::take(&active, self.limits.max_connections);
                let Some(slot) = slot else {
                    respond(&client, 503, "too many connections");
                    continue;
                };
                // A thread that cannot start drops (closes) this connection;
                // `scope.spawn` would panic and take the proxy down instead.
                let _ = thread::Builder::new().spawn_scoped(scope, move || {
                    let _slot = slot;
                    self.handle(&client, addresses);
                });
            }
        })
    }

    fn handle(&self, client: &TcpStream, addresses: &CompiledPolicy<'_>) {
        let started = Instant::now();
        let timeout = Some(self.limits.handshake_timeout);
        if client.set_read_timeout(timeout).is_err() || client.set_write_timeout(timeout).is_err() {
            return;
        }
        let mut buf = Vec::new();
        let deadline = started + self.limits.handshake_timeout;
        let request = match read_head(client, &mut buf, self.limits.max_head_bytes, deadline) {
            Ok(request) => request,
            Err(why) => {
                let decision = Decision::single(Verdict::Deny, RULE_REQUEST, why);
                self.record(None, &decision, started);
                refuse(client, 400, &decision.reasons[0]);
                return;
            }
        };
        // `buf` holds the head and any body bytes read with it. Watching all of
        // it before `rest` is split off leaves its end in the watch's tail, so a
        // secret split between `rest` and the next body chunk is still found.
        let mut watch = Watch::new(self.broker, request.host());
        if let Some(leak) = watch.next(&buf) {
            let decision = leak.decision(request.host());
            self.record(Some(&request), &decision, started);
            refuse(client, 403, &summary(&decision));
            return;
        }
        let rest = buf.split_off(request.head_len);
        let decision = decide::host(self.policy, request.host());
        if decision.verdict != Verdict::Allow {
            self.record(Some(&request), &decision, started);
            refuse(client, 403, &summary(&decision));
            return;
        }
        // A plain-HTTP request is one request: its body is forwarded, and
        // nothing the client sends after it (body.rs). A tunnel carries TLS,
        // where the proxy cannot see a secret or a second request.
        let mut body = BodyEnd::new(match &request.target {
            Target::Http { head, .. } => body::framing(head),
            Target::Connect { .. } => Framing::None,
        });
        let Ok(body_in_rest) = body.feed(&rest) else {
            let decision = Decision::single(Verdict::Deny, RULE_REQUEST, MALFORMED_CHUNKS);
            self.record(Some(&request), &decision, started);
            refuse(client, 400, MALFORMED_CHUNKS);
            return;
        };
        let upstream = match upstream::connect(
            self.resolver,
            request.host(),
            request.port(),
            addresses,
            self.loopback_ok,
            self.limits.connect_timeout,
        ) {
            Ok(upstream) => upstream,
            Err(refusal) => {
                let decision = refusal.decision(request.host());
                self.record(Some(&request), &decision, started);
                let status = if matches!(refusal, Refusal::Address(..) | Refusal::Denied(..)) {
                    403
                } else {
                    502
                };
                refuse(client, status, &summary(&decision));
                return;
            }
        };
        // The body keeps being watched for brokered secrets as it goes by.
        let mut inspect = |chunk: &[u8]| {
            let Ok(n) = body.feed(chunk) else {
                return Forward::Stop;
            };
            if let Some(leak) = watch.next(&chunk[..n]) {
                self.record(Some(&request), &leak.decision(request.host()), started);
                return Forward::Stop;
            }
            if n < chunk.len() || body.done() {
                Forward::Part(n)
            } else {
                Forward::All
            }
        };
        let (first_bytes, inspect) = match &request.target {
            Target::Connect { host, .. } => {
                match self.check_tunnel(client, host, rest, &decision, &request, started) {
                    Some(hello) => (Zeroizing::new(hello), None),
                    None => return,
                }
            }
            Target::Http { head, host, .. } => {
                let mut decision = decision.clone();
                decision
                    .reasons
                    .extend(self.broker.withheld(host).iter().map(|id| {
                        format!("secret `{id}` not injected: plain HTTP needs `plain_http: true`")
                    }));
                if !self.record(Some(&request), &decision, started) {
                    refuse(client, 403, "audit log unavailable");
                    return;
                }
                let inspect: tunnel::Inspect<'_> = &mut inspect;
                // Only the owner host's head carries a value; it is zeroed
                // with `first_bytes` once written.
                let injected = self.broker.inject(host, head);
                let head = injected.as_deref().map_or(head.as_slice(), Vec::as_slice);
                let body_bytes = &rest[..body_in_rest];
                (Zeroizing::new([head, body_bytes].concat()), Some(inspect))
            }
        };
        if (&upstream).write_all(&first_bytes).is_ok() {
            tunnel::relay(client, &upstream, self.limits.idle_timeout, inspect);
        }
    }

    /// Answer the CONNECT, then hold the tunnel's first bytes until its SNI
    /// is known to name the CONNECT host. Returns the bytes to forward. Every
    /// outcome is recorded, a client that cannot be answered too: the
    /// upstream connection is already open.
    fn check_tunnel(
        &self,
        client: &TcpStream,
        host: &str,
        mut hello: Vec<u8>,
        allowed: &Decision,
        request: &Request,
        started: Instant,
    ) -> Option<Vec<u8>> {
        let answered = (&*client).write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let deadline = Instant::now() + self.limits.handshake_timeout;
        let read = answered
            .map_err(|e| format!("answering the CONNECT: {e}"))
            .and_then(|()| read_hello(client, &mut hello, deadline));
        let refusal = match read {
            // With ECH the server acts on the encrypted inner name, which may
            // be another site behind the same provider as the allowed host.
            Ok((_, true)) if !self.allow_ech => Some(format!(
                "TLS ClientHello for CONNECT {host} carries an encrypted server name (ECH), \
                 so the server may serve another site; `sandbox.proxy_allow_ech: true` \
                 in the policy allows it"
            )),
            Ok((Some(name), _)) if name == host => None,
            Ok((Some(name), _)) => Some(format!(
                "TLS server name {name} does not match CONNECT {host}"
            )),
            // An IP literal is never sent as SNI (RFC 6066 §3). The bytes are
            // still a complete `ClientHello`: anything else is an `Err`.
            Ok((None, _)) if host.parse::<std::net::IpAddr>().is_ok() => None,
            Ok((None, _)) => Some(format!(
                "TLS ClientHello for CONNECT {host} has no server name"
            )),
            Err(why) => Some(why),
        };
        if let Some(why) = refusal {
            let decision = Decision::single(Verdict::Deny, RULE_SNI, why);
            self.record(Some(request), &decision, started);
            return None;
        }
        self.record(Some(request), allowed, started)
            .then_some(hello)
    }

    /// Record a decision; `false` when it could not be recorded, which the
    /// caller must treat as a deny.
    fn record(&self, request: Option<&Request>, decision: &Decision, started: Instant) -> bool {
        let connection = Connection {
            method: request.map(|r| r.method.as_str()),
            destination: request.map(|r| (r.host(), r.port())),
            decision,
            latency_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        match self.recorder.record(&connection) {
            Ok(()) => true,
            Err(error) => {
                // The caller refuses the connection; the recorder reports the
                // failure elsewhere, since the audit log is what failed.
                self.recorder.unrecorded(&error);
                false
            }
        }
    }
}

/// One of the `max_connections` slots, released when dropped, even if the
/// connection's thread panics.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn take(active: &'a AtomicUsize, max: usize) -> Option<Self> {
        // A slot taken over the cap is given back at once; the count never
        // stays above `max`.
        let slot = Self(active);
        (active.fetch_add(1, Ordering::AcqRel) < max).then_some(slot)
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Read until a complete request head is in `buf`.
fn read_head(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> Result<Request, String> {
    loop {
        match request::parse(buf) {
            Ok(Some(request)) => return Ok(request),
            Ok(None) if buf.len() >= max => {
                return Err(format!("request head larger than {max} bytes"));
            }
            Ok(None) => read_more(client, buf, max, deadline)?,
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Read until `buf` holds a complete `ClientHello`; its SNI, if any, and
/// whether it carries an encrypted server name (ECH or ESNI).
fn read_hello(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(Option<String>, bool), String> {
    // Records add 5 bytes per 16 KiB of handshake, so this covers MAX_HELLO.
    let max = sni::MAX_HELLO + 1024;
    loop {
        match sni::server_name(buf) {
            Ok(Hello::ServerName(name)) => return Ok((name, false)),
            Ok(Hello::Encrypted(name)) => return Ok((name, true)),
            Ok(Hello::Incomplete) if buf.len() >= max => {
                return Err(sni::HelloError::TooLarge.to_string());
            }
            Ok(Hello::Incomplete) => read_more(client, buf, max, deadline)?,
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// One read, bounded by `deadline` for the whole head or `ClientHello`, so a
/// client trickling one byte at a time cannot hold its slot indefinitely.
fn read_more(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() || client.set_read_timeout(Some(left)).is_err() {
        return Err("the client did not finish its handshake in time".to_owned());
    }
    let mut chunk = [0u8; 4096];
    let want = chunk.len().min(max.saturating_sub(buf.len())).max(1);
    match (&*client).read(&mut chunk[..want]) {
        Ok(0) => Err("client closed the connection early".to_owned()),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
        Err(e) => Err(format!("reading from the client: {e}")),
    }
}

fn summary(decision: &Decision) -> String {
    format!(
        "{} ({})",
        decision.reasons.join("; "),
        decision.rules.join(", ")
    )
}

/// Answer `status` from a connection's own thread, then close it so the
/// client can read the answer.
///
/// Closing a socket with unread input resets the connection, and on Windows
/// the reset discards the answer before the client reads it. So stop writing,
/// then drain what the client still sends, bounded by [`LINGER`] and
/// [`LINGER_BYTES`], before the socket is dropped.
fn refuse(client: &TcpStream, status: u16, message: &str) {
    respond(client, status, message);
    let _ = client.shutdown(Shutdown::Write);
    let until = Instant::now() + LINGER;
    let mut left = LINGER_BYTES;
    let mut sink = [0; 8192];
    while left > 0 {
        let rest = until.saturating_duration_since(Instant::now());
        if rest.is_zero() || client.set_read_timeout(Some(rest)).is_err() {
            return;
        }
        match (&*client).read(&mut sink) {
            Ok(0) | Err(_) => return,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
}

fn respond(client: &TcpStream, status: u16, message: &str) {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        _ => "Service Unavailable",
    };
    // The message may quote the request; no control byte of it is echoed.
    let message: String = message
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let body = format!("moat proxy: {message}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = (&*client).write_all(response.as_bytes());
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests;
