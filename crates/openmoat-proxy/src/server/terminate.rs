//! A CONNECT the proxy terminates (ADR-043, ADR-062): decided like any
//! tunnel, its `ClientHello` checked against the CONNECT host as for any
//! tunnel, then handed to `exchange.rs`, which reads the request inside.
//!
//! Which tunnels are terminated, and what a session's taint does to them:
//!
//! - A host one of whose secrets says `tls: terminate`, for a session whose
//!   commands trust the CA in full (`openmoat run`, [`Trust::All`]).
//! - A host with request rules (`requests:`), for a session that trusts the CA
//!   for them ([`Trust::Requests`] too: the standalone proxy's sessions that
//!   received the trust files). A connection to such a host that cannot be
//!   terminated is refused or relayed as `requests_untrusted` says.
//! - After the session read secret material, a terminated tunnel to a
//!   `requests:` host is kept open for reads: `GET`, `HEAD` and `OPTIONS`
//!   without a body pass, anything else is refused with `session-taint`.
//!   Every other host keeps the whole-host refusal.

use std::net::TcpStream;

use openmoat_core::Decision;
use openmoat_core::rule_id::SESSION_TAINT;

use super::{Proxy, Served, Turn};
use crate::audit::Connection;
use crate::exchange::Tunnel;
use crate::request::{Request, Target};
use crate::session::Trust;
use crate::tls::Tls;
use crate::upstream::{self, Refusal};

/// What a terminated tunnel starts with.
pub(super) struct Opened<'d> {
    /// The host's allow decision.
    pub(super) allowed: &'d Decision,
    /// What the client sent after the CONNECT head.
    pub(super) rest: Vec<u8>,
    /// The session read secret material: only reads without a body pass.
    pub(super) reads_only: bool,
}

impl Proxy<'_> {
    /// The termination a CONNECT to `host` gets: TLS is set up for this
    /// proxy, and the host is one the session's trust lets it terminate. A
    /// request served without a credential is never terminated: it is
    /// relayed as any tunnel, and HTTPS there keeps the placeholder.
    pub(super) fn terminating(&self, host: &str, turn: Turn<'_>) -> Option<&Tls> {
        let listed = match turn.trust {
            Trust::All => self.broker.terminates(host) || self.requests.names(host),
            Trust::Requests => self.requests.names(host),
            _ => false,
        };
        self.tls.filter(|_| turn.session.is_some() && listed)
    }

    /// The session's taint and, for a CONNECT to a `requests:` host, whether
    /// it can be terminated: `Err` the refusal to record; `Ok` whether the
    /// terminated tunnel may only read (ADR-062 §3). A tunnel relayed unread
    /// under `requests_untrusted: relay` gets the note on `allowed`.
    pub(super) fn gate(
        &self,
        turn: Turn<'_>,
        request: &Request,
        allowed: &mut Decision,
    ) -> Result<bool, Decision> {
        let host = request.host();
        let ruled = matches!(request.target, Target::Connect { .. }) && self.requests.names(host);
        let terminated = ruled && self.terminating(host, turn).is_some();
        if ruled && !terminated {
            let why = if self.tls.is_none() {
                "the proxy has no certificate authority that covers it"
            } else if turn.session.is_none() {
                "the request carries no session credential"
            } else {
                "this session's commands were not given the proxy's certificate authority"
            };
            allowed.reasons.push(self.requests.untrusted(host, why)?);
        }
        match self.tainted(turn, request, None) {
            None => Ok(false),
            Some(taint) if terminated && is_taint(&taint) => Ok(true),
            Some(refusal) => Err(refusal),
        }
    }

    /// Serve a terminated tunnel.
    pub(super) fn terminate(
        &self,
        client: &TcpStream,
        request: &Request,
        turn: Turn<'_>,
        opened: Opened<'_>,
        served: &Served<'_>,
        tls: &Tls,
    ) {
        let (host, port) = (request.host(), request.port());
        let allowed = opened.allowed;
        let mut row = allowed.clone();
        let why = if self.requests.names(host) {
            "its request rules"
        } else {
            "its brokered secrets"
        };
        row.reasons.push(format!(
            "TLS to {host} is terminated for {why}: each request in the tunnel is read, checked \
             and recorded"
        ));
        if opened.reads_only {
            row.reasons.push(
                "the session read secret material, so only GET, HEAD and OPTIONS requests \
                 without a body pass in this tunnel"
                    .to_owned(),
            );
        }
        let Some(hello) = self.check_tunnel(client, host, opened.rest, &row, request, turn) else {
            return;
        };
        let record = |method: Option<&str>, decision: &Decision| {
            self.write_row(&Connection {
                session: turn.session,
                method,
                destination: Some((host, port)),
                terminated: true,
                decision,
                latency_us: u64::try_from(turn.started.elapsed().as_micros()).unwrap_or(u64::MAX),
            })
        };
        // A `requests:` host stays open to reads once the session is tainted;
        // a history that cannot be read still closes it.
        let ruled = self.requests.names(host);
        let still_allowed = || {
            if !ruled {
                return self.still_untainted(turn, request);
            }
            match self.tainted(turn, request, Some(self.limits.taint_recheck)) {
                Some(refusal) if !is_taint(&refusal) => {
                    self.record(turn, Some(request), &refusal);
                    false
                }
                _ => true,
            }
        };
        let reads_only = || {
            opened.reads_only
                || (ruled
                    && self
                        .tainted(turn, request, Some(self.limits.taint_recheck))
                        .is_some_and(|t| is_taint(&t)))
        };
        let tunnel = Tunnel {
            host,
            port,
            broker: self.broker,
            requests: self.requests,
            tls,
            limits: self.limits,
            allowed,
            record: &record,
            still_allowed: &still_allowed,
            reads_only: &reads_only,
        };
        let mut connect = || {
            upstream::connect(
                self.resolver,
                host,
                port,
                served.addresses,
                self.loopback_ok,
                self.limits.connect_timeout,
            )
            .map_err(|refusal| {
                let status = if matches!(refusal, Refusal::Address(..) | Refusal::Denied(..)) {
                    403
                } else {
                    502
                };
                (status, refusal.decision(host))
            })
        };
        tunnel.serve(client, &hello, &mut connect);
    }
}

/// Whether `decision` is the refusal a session's taint makes, not one for a
/// history that cannot be read.
fn is_taint(decision: &Decision) -> bool {
    decision.rules.iter().any(|r| r == SESSION_TAINT)
}
