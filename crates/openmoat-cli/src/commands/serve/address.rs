//! Where `openmoat serve` may listen: 127.0.0.1 or `::1`, nothing else.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, ensure};

/// `addr` when it is 127.0.0.1 or `::1` (any port). Any other address, other
/// loopback addresses (127.0.0.2) and IPv4-mapped forms included, is refused:
/// the views carry the audit log, and the one address a person checks is
/// the one the link names.
pub fn check(addr: SocketAddr) -> Result<SocketAddr> {
    let ip = addr.ip();
    ensure!(
        ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST),
        "--listen {addr}: `openmoat serve` listens on 127.0.0.1 or [::1] only, so that no \
         other machine can reach what it shows"
    );
    Ok(addr)
}

/// The `Host` header values a browser sends for this server: the loopback
/// names with `port`, and without it on port 80, where browsers leave it out.
/// Anything else is another name that resolves here (DNS rebinding).
pub fn host_names(port: u16) -> Vec<String> {
    let names = ["127.0.0.1", "localhost", "[::1]"];
    let mut out: Vec<String> = names.iter().map(|n| format!("{n}:{port}")).collect();
    if port == 80 {
        out.extend(names.iter().map(|n| (*n).to_owned()));
    }
    out
}
