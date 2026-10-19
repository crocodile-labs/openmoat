//! The sandboxed side: `moat guard` under `moat run` sends its payload out.

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_hosts::Host;
use zeroize::Zeroizing;

use super::wire::{NONCE_LEN, Reply, Request};
use super::{SOCKET_ENV, Stream, TOKEN_ENV, random_hex};

/// Where `moat run` decides, and the token it wants.
pub struct Endpoint {
    addr: SocketAddr,
    token: Zeroizing<String>,
}

/// The endpoint the environment names; `None` when neither variable is set,
/// an error when only one is or the address is not a loopback one.
pub fn configured(var: &dyn Fn(&str) -> Option<String>) -> Option<Result<Endpoint>> {
    let (socket, token) = (var(SOCKET_ENV), var(TOKEN_ENV).map(Zeroizing::new));
    if socket.is_none() && token.is_none() {
        return None;
    }
    Some(endpoint(socket, token))
}

fn endpoint(socket: Option<String>, token: Option<Zeroizing<String>>) -> Result<Endpoint> {
    let (Some(socket), Some(token)) = (socket, token) else {
        bail!("only one of {SOCKET_ENV} and {TOKEN_ENV} is set");
    };
    let addr: SocketAddr = socket
        .parse()
        .with_context(|| format!("{SOCKET_ENV} is not an address: {socket}"))?;
    // The payload may quote secrets the agent read: it never leaves the machine.
    ensure!(
        addr.ip().is_loopback(),
        "{SOCKET_ENV} is not a loopback address"
    );
    ensure!(!token.is_empty(), "{TOKEN_ENV} is empty");
    Ok(Endpoint { addr, token })
}

impl Endpoint {
    /// Send one hook call and wait at most `budget` for its answer.
    pub fn decide(
        &self,
        host: Host,
        payload: &str,
        continue_cli: bool,
        budget: Duration,
    ) -> Result<Reply> {
        let deadline = Instant::now() + budget;
        let stream = TcpStream::connect_timeout(&self.addr, budget)
            .with_context(|| format!("connecting to `moat run` at {}", self.addr))?;
        let cwd = std::env::current_dir()
            .ok()
            .and_then(|d| d.to_str().map(str::to_owned))
            .unwrap_or_default();
        let request = Request {
            token: Zeroizing::new(self.token.as_bytes().to_vec()),
            nonce: random_hex(NONCE_LEN / 2)?.to_string(),
            host: host.id().to_owned(),
            cwd,
            continue_cli,
            payload: payload.to_owned(),
        };
        exchange(stream, &request, deadline)
    }
}

/// Write `request` on `stream` and read the reply before `deadline`. Each
/// read and write waits at most until then; the guard's own time limit
/// (`deny_when_over_budget`) ends a reply that trickles in past it.
pub fn exchange(mut stream: impl Stream, request: &Request, deadline: Instant) -> Result<Reply> {
    let left = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .context("no answer within the guard's time limit")
    };
    stream.set_timeouts(left()?)?;
    request
        .write_to(&mut stream)
        .context("sending the hook call to `moat run`")?;
    stream.set_timeouts(left()?)?;
    Reply::read_from(&mut stream, &request.nonce).context("reading `moat run`'s answer")
}
