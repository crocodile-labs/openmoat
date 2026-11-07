//! A CONNECT the proxy terminates (ADR-043): decided like any tunnel, its
//! `ClientHello` checked against the CONNECT host as for any tunnel, then
//! handed to `exchange.rs`, which reads the request inside.

use std::net::TcpStream;

use openmoat_core::Decision;

use super::{Proxy, Served, Turn};
use crate::audit::Connection;
use crate::exchange::Tunnel;
use crate::request::Request;
use crate::tls::Tls;
use crate::upstream::{self, Refusal};

impl Proxy<'_> {
    /// The termination a CONNECT to `host` gets: TLS is set up for this proxy,
    /// one of the host's secrets says `tls: terminate` or the host has request
    /// rules (ADR-062), and the request is an authenticated session's
    /// (ADR-044), whose taint then applies inside the tunnel. A request served
    /// without a credential is never terminated: it is relayed as any tunnel,
    /// and HTTPS there keeps the placeholder.
    pub(super) fn terminating(&self, host: &str, turn: Turn<'_>) -> Option<&Tls> {
        let listed = self.broker.terminates(host) || self.requests.names(host);
        self.tls.filter(|_| turn.session.is_some() && listed)
    }

    /// Serve a terminated tunnel. `allowed` is the host's decision; `rest`
    /// what the client sent after the CONNECT head.
    #[expect(
        clippy::too_many_arguments,
        reason = "the connection's state as `handle` holds it; a struct would only rename it"
    )]
    pub(super) fn terminate(
        &self,
        client: &TcpStream,
        request: &Request,
        turn: Turn<'_>,
        allowed: &Decision,
        rest: Vec<u8>,
        served: &Served<'_>,
        tls: &Tls,
    ) {
        let (host, port) = (request.host(), request.port());
        let mut opened = allowed.clone();
        let why = if self.broker.terminates(host) {
            "its brokered secrets"
        } else {
            "its request rules"
        };
        opened.reasons.push(format!(
            "TLS to {host} is terminated for {why}: each request in the tunnel is read, checked \
             and recorded"
        ));
        let Some(hello) = self.check_tunnel(client, host, rest, &opened, request, turn) else {
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
        let still_allowed = || self.still_untainted(turn, request);
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
