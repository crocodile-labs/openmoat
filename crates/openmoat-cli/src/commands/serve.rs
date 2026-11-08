//! `openmoat serve` (ADR-066): what `status`, `show`, `report` and `why` show,
//! in a browser on this machine.
//!
//! It listens on 127.0.0.1 or `::1` only ([`address`]), makes a token for the
//! run and prints it once in the link ([`token`]), and answers a request only
//! when the request names this server by a loopback name, comes from no other
//! site, is a `GET` and carries the token ([`request`]). Every view is built by
//! the command that prints it ([`routes`]), from the audit log opened read-only
//! and the policy files; no path changes anything. A person starts it at a
//! terminal: an agent is refused here, as for the other person-only commands,
//! and denied by the policy before it runs (`kernel-self`).

mod address;
mod page;
mod request;
mod response;
mod routes;
mod token;

#[cfg(test)]
mod tests;

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use self::request::MAX_HEAD;
use self::response::Response;
use self::token::Token;
use crate::cli::ServeArgs;
use crate::exit::Code;
use crate::home::Home;

/// How long one connection may take to send its request and read the answer.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The most connections answered at once; more are closed unanswered.
const MAX_CONNECTIONS: usize = 8;

/// One run's server state.
struct Server {
    token: Token,
    port: u16,
    open: AtomicUsize,
}

pub fn run(args: &ServeArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat serve")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat serve` must be run by a person in a terminal, not from a hook or \
             script: its link opens the audit log to whoever holds it"
        );
    }
    let listen = address::check(args.listen)?;
    // Refuse to start where there is nothing to show.
    Home::locate()?.open_audit()?;
    let token = Token::generate()?;
    let listener = TcpListener::bind(listen).with_context(|| format!("listening on {listen}"))?;
    let addr = listener
        .local_addr()
        .context("reading the listening address")?;
    let server = Arc::new(Server {
        token,
        port: addr.port(),
        open: AtomicUsize::new(0),
    });
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "openmoat serve: read-only, on this machine only. Open\n  {}\n\
         The link works until this stops (Ctrl-C). Anyone holding it can read what \
         `openmoat status`, `show`, `report` and `why` show; do not share it.",
        link(addr, &server.token)
    )?;
    stdout.flush()?;
    drop(stdout);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => accept(&server, stream),
            Err(error) => eprintln!("openmoat serve: accepting a connection: {error}"),
        }
    }
    Ok(Code::Ok)
}

/// The link printed at start: the only place the token is shown.
fn link(addr: SocketAddr, token: &Token) -> String {
    format!("http://{addr}/?token={}", token.as_str())
}

/// Answer `stream` on a thread of its own, unless [`MAX_CONNECTIONS`] are
/// open already or the peer is not on loopback.
fn accept(server: &Arc<Server>, stream: TcpStream) {
    let local = stream.peer_addr().is_ok_and(|peer| peer.ip().is_loopback());
    if !local || server.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        if local {
            server.open.fetch_sub(1, Ordering::SeqCst);
        }
        return;
    }
    let server = Arc::clone(server);
    std::thread::spawn(move || {
        if let Err(error) = server.connection(stream) {
            eprintln!("openmoat serve: {error:#}");
        }
        server.open.fetch_sub(1, Ordering::SeqCst);
    });
}

impl Server {
    /// Read one request from `stream` and write its answer.
    fn connection(&self, mut stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let mut head = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let response = loop {
            let n = match stream.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break Response::text(408, "the request took too long");
                }
                Err(e) => return Err(e).context("reading a request"),
            };
            head.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if let Some(response) = self.answer(&head) {
                break response;
            }
            if head.len() >= MAX_HEAD {
                break Response::text(431, "the request head is too long");
            }
        };
        if matches!(response.status, 401 | 403) {
            eprintln!(
                "openmoat serve: refused a request ({}): {}",
                response.status,
                String::from_utf8_lossy(&response.body).trim()
            );
        }
        response.write_to(&mut stream).context("writing a response")
    }

    /// The answer to the request head in `head`; `None` while it is
    /// incomplete. Nothing is read for a request before it passes
    /// [`request::check`].
    fn answer(&self, head: &[u8]) -> Option<Response> {
        let req = match request::parse(head) {
            Ok(Some(req)) => req,
            Ok(None) => return None,
            Err(response) => return Some(response),
        };
        if let Err(response) = request::check(&req, self.port, &self.token) {
            return Some(response);
        }
        Some(match routes::route(&req) {
            Ok(target) => routes::answer(&target, &req, &self.token),
            Err(response) => response,
        })
    }
}
