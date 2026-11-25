//! The loopback port the run's proxy (and the hook relay beside it) listens
//! on: any free one, except as the Windows agent account, whose network
//! filters let the agent reach only the range setup recorded (ADR-129 §2,
//! "Network"); there the first free port of that range, checked to be the
//! one this process holds.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};

use anyhow::{Context as _, Result};

use crate::agent_account::wfp;

/// The proxy's listener and its port: on a port of `range` when there is
/// one, otherwise on any free loopback port.
pub fn listen(range: Option<[u16; 2]>) -> Result<(TcpListener, u16)> {
    let Some(range) = range else {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("listening on a loopback port for the proxy")?;
        let port = listener.local_addr()?.port();
        return Ok((listener, port));
    };
    wfp::choose_port(
        range,
        |port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)),
        |listener| match listener.local_addr() {
            Ok(SocketAddr::V4(addr)) if *addr.ip() == Ipv4Addr::LOCALHOST => Some(addr.port()),
            _ => None,
        },
    )
}
