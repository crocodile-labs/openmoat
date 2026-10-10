//! Resolving and connecting to the destination.
//!
//! The proxy resolves names itself and checks every address it gets back
//! before connecting to one of exactly those addresses, so the check and the
//! connection cannot disagree (no second lookup an attacker could race).

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use openmoat_core::{CompiledPolicy, Decision, Verdict};

use crate::decide::{self, Forbidden, RULE_ADDRESS, RULE_UPSTREAM};

/// Name resolution, injectable so tests can map names without a DNS server.
pub trait Resolve: Send + Sync {
    /// Every address the DNS name `host` resolves to, with `port` attached.
    /// IP literals never reach the resolver.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The operating system's resolver (`getaddrinfo` and its equivalents).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Why no connection was made.
#[derive(Debug)]
#[non_exhaustive]
pub enum Refusal {
    /// A resolved address the proxy never connects to.
    Address(SocketAddr, Forbidden),
    /// The name did not resolve, or no address accepted the connection.
    Unreachable(String),
}

impl Refusal {
    /// The decision recorded for this refusal.
    #[must_use]
    pub fn decision(&self, host: &str) -> Decision {
        match self {
            Self::Address(addr, why) => Decision::single(
                Verdict::Deny,
                RULE_ADDRESS,
                format!("{host} resolves to {}, {}", addr.ip(), why.describe()),
            ),
            Self::Unreachable(why) => Decision::single(Verdict::Deny, RULE_UPSTREAM, why.clone()),
        }
    }
}

/// Resolve `host`, refuse if any address is forbidden, then connect to the
/// first address that answers. A private address passes only when
/// `addresses` (compiled from [`decide::address_policy`]) names it.
/// `loopback_ok` lists loopback addresses that may be reached anyway (tests);
/// nothing exempts link-local or metadata.
pub fn connect(
    resolver: &dyn Resolve,
    host: &str,
    port: u16,
    addresses: &CompiledPolicy<'_>,
    loopback_ok: &[SocketAddr],
    timeout: Duration,
) -> Result<TcpStream, Refusal> {
    let addrs = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => resolver
            .resolve(host, port)
            .map_err(|e| Refusal::Unreachable(format!("cannot resolve {host}: {e}")))?,
    };
    if addrs.is_empty() {
        return Err(Refusal::Unreachable(format!("{host} has no addresses")));
    }
    // One bad address refuses the name: an allowed name that also points at
    // a metadata service is an attack, not a fallback.
    for addr in &addrs {
        match decide::forbidden(addr.ip()) {
            Some(Forbidden::Loopback) if loopback_ok.contains(addr) => {}
            Some(Forbidden::Private(_)) if decide::named(addresses, addr.ip()) => {}
            Some(why) => return Err(Refusal::Address(*addr, why)),
            None => {}
        }
    }
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(Refusal::Unreachable(match last {
        Some(e) => format!("cannot connect to {host}:{port}: {e}"),
        None => format!("cannot connect to {host}:{port}"),
    }))
}
