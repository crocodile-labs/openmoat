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
        let stream = connect_retrying(
            |limit| TcpStream::connect_timeout(&self.addr, limit),
            deadline,
        )
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

/// How long to wait before connecting again after the sandbox refused.
const REFUSED_PAUSE: Duration = Duration::from_millis(20);
/// The most connects one call makes.
const CONNECT_ATTEMPTS: u32 = 10;

/// `connect(limit)` until it opens, before `deadline`. On some macOS 14
/// machines Seatbelt refuses, with EPERM, a connect that the profile's
/// `localhost:<port>` rule allows, for a few milliseconds about every 15 s
/// (#280, #588); only that refusal is tried again, a few times, and anything
/// else, or a refusal that lasts, is the error the guard denies with.
pub fn connect_retrying<S>(
    mut connect: impl FnMut(Duration) -> std::io::Result<S>,
    deadline: Instant,
) -> std::io::Result<S> {
    let mut attempt = 1;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        match connect(left) {
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && attempt < CONNECT_ATTEMPTS
                    && left > REFUSED_PAUSE * 2 =>
            {
                attempt += 1;
                std::thread::sleep(REFUSED_PAUSE);
            }
            result => return result,
        }
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
