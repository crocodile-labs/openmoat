//! Accepting connections and deciding each one.
//!
//! Order per connection: read the head → (session mode) verify its credential
//! and take the session's share of the slots → check it for brokered secrets
//! bound elsewhere → decide the host → (session mode) apply the session's
//! taint → resolve and check the addresses → connect → (CONNECT) answer 200,
//! read the `ClientHello` and check its SNI → record → relay, watching a
//! plain-HTTP body for brokered secrets too, and (session mode) checking the
//! session's taint again every so often (`recheck.rs`). Nothing reaches the
//! destination before the record is written; a failed record closes the
//! connection. Connections refused at accept for capacity are recorded in
//! coalesced rows (`capacity.rs`).

mod capacity;
mod limits;
mod recheck;
mod terminate;
mod wire;

use std::io::{self, ErrorKind, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use openmoat_core::{CompiledPolicy, Decision, Verdict};
use zeroize::Zeroizing;

pub use self::capacity::RULE_CAPACITY;
use self::capacity::{Full, Refusals};
pub use self::limits::Limits;
pub(crate) use self::wire::response;
use self::wire::{read_head, read_hello, refuse, respond, summary};
use crate::audit::{Connection, Recorder};
use crate::body::{self, BodyEnd, Framing};
use crate::broker::{Broker, Channel, Watch};
use crate::decide::{self, RULE_REQUEST, RULE_SNI};
use crate::local::{self, LocalService};
use crate::request::{Request, Target};
use crate::session::{AuthError, RULE_SESSION, Sessions};
use crate::slots::{PENDING, Share, Shares, WITHOUT_CREDENTIAL};
use crate::tls::Tls;
use crate::tunnel::{self, Forward};
use crate::upstream::{self, Refusal, Resolve};

/// Why a request whose chunked body cannot be followed is refused.
const MALFORMED_CHUNKS: &str = "malformed chunked request body";

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
    /// Session mode (ADR-027, ADR-044): every request must carry one of these
    /// credentials, and is decided with that session's taint and connection
    /// share. `None` serves any local client with no session; `moat run` and
    /// `moat proxy` always serve sessions.
    pub sessions: Option<&'a Sessions<'a>>,
    /// A service of this process that shares the port (ADR-028): `moat run`
    /// answers its sandboxed hooks here. `None` in `moat proxy`.
    pub local: Option<&'a dyn LocalService>,
    /// TLS termination (ADR-043): a CONNECT to the host of a secret that says
    /// `tls: terminate` is decrypted, and each request in it checked, given
    /// the value and recorded. `None`: every tunnel is relayed as it is, as
    /// in `moat proxy`, whose clients cannot be made to trust the CA.
    pub tls: Option<&'a Tls>,
}

impl std::fmt::Debug for Proxy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("limits", &self.limits)
            .field("broker", &self.broker)
            .field("loopback_ok", &self.loopback_ok)
            .field("allow_ech", &self.allow_ech)
            .field("sessions", &self.sessions)
            .field("local", &self.local.is_some())
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

/// What every connection of one [`Proxy::serve`] shares.
struct Served<'s> {
    addresses: &'s CompiledPolicy<'s>,
    /// [`decide::port_policy`] of the policy, compiled.
    ports: &'s CompiledPolicy<'s>,
    shares: Shares,
}

/// One connection's session (`None` without session mode) and start time,
/// which each of its audit rows carries.
#[derive(Clone, Copy)]
struct Turn<'s> {
    session: Option<&'s str>,
    started: Instant,
}

impl Proxy<'_> {
    /// Serve connections from `listener` until accepting fails.
    /// Fails at once when the [`Limits`] are zero or too large.
    pub fn serve(&self, listener: &TcpListener) -> io::Result<()> {
        self.limits.check()?;
        let address_policy = decide::address_policy(self.policy.policy());
        let addresses = CompiledPolicy::compile(&address_policy, self.policy.context())
            .map_err(io::Error::other)?;
        let port_policy = decide::port_policy(self.policy.policy());
        let ports = CompiledPolicy::compile(&port_policy, self.policy.context())
            .map_err(io::Error::other)?;
        let served = Served {
            addresses: &addresses,
            ports: &ports,
            shares: Shares::new(self.limits.max_connections),
        };
        let served = &served;
        let active = AtomicUsize::new(0);
        let refusals = Refusals::default();
        thread::scope(|scope| {
            loop {
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(e) if is_transient(&e) => continue,
                    Err(e) => return Err(e),
                };
                refusals.flush(self.recorder, Instant::now());
                let _ = client.set_write_timeout(Some(self.limits.handshake_timeout));
                let full = |kind: Full| {
                    respond(&client, 503, kind.reply());
                    refusals.refused(kind, self.recorder, Instant::now());
                };
                let slot = Slot::take(&active, self.limits.max_connections);
                let Some(slot) = slot else {
                    full(Full::Slots);
                    continue;
                };
                // Until it authenticates, a connection counts against the
                // share of all such connections (#555).
                let pending = if self.sessions.is_some() {
                    let Some(share) = served.shares.take(PENDING) else {
                        full(Full::Pending);
                        continue;
                    };
                    Some(share)
                } else {
                    None
                };
                // A thread that cannot start drops (closes) this connection;
                // `scope.spawn` would panic and take the proxy down instead.
                let _ = thread::Builder::new().spawn_scoped(scope, move || {
                    let _slot = slot;
                    self.handle(&client, served, pending);
                });
            }
        })
    }

    fn handle(&self, client: &TcpStream, served: &Served<'_>, pending: Option<Share<'_>>) {
        let started = Instant::now();
        let timeout = Some(self.limits.handshake_timeout);
        if client.set_read_timeout(timeout).is_err() || client.set_write_timeout(timeout).is_err() {
            return;
        }
        // The head may hold the session's credential: zeroed once dropped.
        let mut buf = Zeroizing::new(Vec::new());
        let deadline = started + self.limits.handshake_timeout;
        // Still counted as waiting to authenticate: the service checks its own token.
        if let Some(local) = self.local
            && !local.prefix().is_empty()
            && local::starts_with(client, local.prefix(), deadline)
        {
            local.serve(client);
            return;
        }
        let request = match read_head(client, &mut buf, self.limits.max_head_bytes, deadline) {
            Ok(request) => request,
            Err(why) => {
                let decision = Decision::single(Verdict::Deny, RULE_REQUEST, why);
                let turn = Turn {
                    session: None,
                    started,
                };
                self.record(turn, None, &decision);
                refuse(client, 400, &decision.reasons[0]);
                return;
            }
        };
        let Some((session, _share)) = self.admit(client, &request, served, started) else {
            return;
        };
        drop(pending);
        let turn = Turn {
            session: session.as_deref(),
            started,
        };
        // `buf` holds the head and any body bytes read with it. Watching all of
        // it before `rest` is split off leaves its end in the watch's tail, so a
        // secret split between `rest` and the next body chunk is still found.
        let mut watch = Watch::new(self.broker, request.host());
        if let Some(leak) = watch.next(&buf) {
            let decision = leak.decision(request.host());
            self.record(turn, Some(&request), &decision);
            refuse(client, 403, &summary(&decision));
            return;
        }
        let rest = Zeroizing::new(buf.split_off(request.head_len));
        let decision = decide::host_port(self.policy, served.ports, request.host(), request.port());
        if decision.verdict != Verdict::Allow {
            self.record(turn, Some(&request), &decision);
            refuse(client, 403, &summary(&decision));
            return;
        }
        if let Some(refusal) = self.tainted(turn, &request, None) {
            self.record(turn, Some(&request), &refusal);
            refuse(client, 403, &summary(&refusal));
            return;
        }
        // A secret's `allow` rules, before anything goes upstream (ADR-043).
        let routed = match &request.target {
            Target::Http { head, host, port } => {
                match self.broker.admit(host, Channel::Plain(*port), head) {
                    Ok(reasons) => reasons,
                    Err(refusal) => {
                        self.record(turn, Some(&request), &refusal);
                        refuse(client, 403, &summary(&refusal));
                        return;
                    }
                }
            }
            Target::Connect { .. } => Vec::new(),
        };
        if let Target::Connect { host, .. } = &request.target
            && let Some(tls) = self.terminating(host, turn)
        {
            self.terminate(
                client,
                &request,
                turn,
                &decision,
                rest.to_vec(),
                served,
                tls,
            );
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
            self.record(turn, Some(&request), &decision);
            refuse(client, 400, MALFORMED_CHUNKS);
            return;
        };
        let upstream = match upstream::connect(
            self.resolver,
            request.host(),
            request.port(),
            served.addresses,
            self.loopback_ok,
            self.limits.connect_timeout,
        ) {
            Ok(upstream) => upstream,
            Err(refusal) => {
                let decision = refusal.decision(request.host());
                self.record(turn, Some(&request), &decision);
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
                // The allow row is already written; this one says it was cut.
                let decision = Decision::single(Verdict::Deny, RULE_REQUEST, MALFORMED_CHUNKS);
                self.record(turn, Some(&request), &decision);
                return Forward::Stop;
            };
            if let Some(leak) = watch.next(&chunk[..n]) {
                self.record(turn, Some(&request), &leak.decision(request.host()));
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
                match self.check_tunnel(client, host, rest.to_vec(), &decision, &request, turn) {
                    Some(hello) => (Zeroizing::new(hello), None),
                    None => return,
                }
            }
            Target::Http { head, host, port } => {
                let mut decision = decision.clone();
                decision.reasons.extend(self.broker.withheld(host, *port));
                decision.reasons.extend(routed);
                if !self.record(turn, Some(&request), &decision) {
                    refuse(client, 403, "audit log unavailable");
                    return;
                }
                let inspect: tunnel::Inspect<'_> = &mut inspect;
                // Only the owner host's head carries a value; it is zeroed
                // with `first_bytes` once written.
                let injected = self.broker.inject(host, Channel::Plain(*port), head);
                let head = injected.as_deref().map_or(head.as_slice(), Vec::as_slice);
                let body_bytes = &rest[..body_in_rest];
                (Zeroizing::new([head, body_bytes].concat()), Some(inspect))
            }
        };
        if (&upstream).write_all(&first_bytes).is_ok() {
            let still_allowed = || self.still_untainted(turn, &request);
            let recheck = turn.session.map(|_| tunnel::Recheck {
                every: self.limits.taint_recheck,
                still_allowed: &still_allowed,
            });
            tunnel::relay(
                client,
                &upstream,
                self.limits.idle_timeout,
                inspect,
                recheck,
            );
        }
    }

    /// The connection's session and its share of the slots, or `None` once
    /// the request has been refused and recorded: a missing or invalid
    /// credential gets `407`, a session holding its share `503`. Without
    /// session mode every request is admitted, with no session; where the
    /// sessions serve requests without a credential, one that carries none
    /// is admitted with no session, in the share of all such requests.
    fn admit<'s>(
        &'s self,
        client: &TcpStream,
        request: &Request,
        served: &'s Served<'_>,
        started: Instant,
    ) -> Option<(Option<String>, Option<Share<'s>>)> {
        let unnamed = Turn {
            session: None,
            started,
        };
        let Some(sessions) = self.sessions else {
            return Some((None, None));
        };
        let (session, holder) = match sessions.verify(&request.credentials) {
            Ok(session) => {
                let holder = session.clone();
                (Some(session), holder)
            }
            Err(AuthError::Missing) if sessions.serves_without_credential() => {
                (None, WITHOUT_CREDENTIAL.to_owned())
            }
            Err(why) => {
                let decision = Decision::single(Verdict::Deny, RULE_SESSION, why.to_string());
                self.record(unnamed, Some(request), &decision);
                refuse(client, 407, &summary(&decision));
                return None;
            }
        };
        if let Some(share) = served.shares.take(&holder) {
            return Some((session, Some(share)));
        }
        let turn = Turn {
            session: session.as_deref(),
            started,
        };
        let holder = if session.is_some() {
            "the session already holds"
        } else {
            "requests without a credential already hold"
        };
        let decision = Decision::single(
            Verdict::Deny,
            RULE_SESSION,
            format!(
                "{holder} {} connections, half of the proxy's",
                served.shares.cap()
            ),
        );
        self.record(turn, Some(request), &decision);
        refuse(client, 503, &summary(&decision));
        None
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
        turn: Turn<'_>,
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
            self.record(turn, Some(request), &decision);
            return None;
        }
        self.record(turn, Some(request), allowed).then_some(hello)
    }

    /// Record a decision; `false` when it could not be recorded, which the
    /// caller must treat as a deny.
    fn record(&self, turn: Turn<'_>, request: Option<&Request>, decision: &Decision) -> bool {
        let connection = Connection {
            session: turn.session,
            method: request.map(|r| r.method.as_str()),
            destination: request.map(|r| (r.host(), r.port())),
            terminated: false,
            decision,
            latency_us: u64::try_from(turn.started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        self.write_row(&connection)
    }

    /// Record `connection`; `false` when it could not be recorded.
    fn write_row(&self, connection: &Connection<'_>) -> bool {
        match self.recorder.record(connection) {
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

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests;
