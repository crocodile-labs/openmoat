//! Reading a request head or `ClientHello` within its deadline, and answering
//! a refused connection.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use openmoat_core::Decision;

use crate::request::{self, Request};
use crate::sni::{self, Hello};

/// How long, and how much input, a refused connection is drained for.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 1 << 20;

/// Most bytes read for a `ClientHello`. Records add 5 bytes per 16 KiB of
/// handshake, so this covers [`sni::MAX_HELLO`].
const MAX_HELLO_READ: usize = sni::MAX_HELLO + 1024;

/// Read until a complete request head is in `buf`.
pub(super) fn read_head(
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
pub(super) fn read_hello(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(Option<String>, bool), String> {
    let max = MAX_HELLO_READ;
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

pub(super) fn summary(decision: &Decision) -> String {
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
pub(super) fn refuse(client: &TcpStream, status: u16, message: &str) {
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

pub(super) fn respond(client: &TcpStream, status: u16, message: &str) {
    let _ = (&*client).write_all(response(status, message).as_bytes());
}

/// The whole answer `respond` sends: `status`, and `message` as a text body.
pub(crate) fn response(status: u16, message: &str) -> String {
    let (reason, extra) = match status {
        400 => ("Bad Request", ""),
        403 => ("Forbidden", ""),
        // A client that sends its credential only when challenged (git's
        // `http.proxyAuthMethod=anyauth`) retries on a new connection.
        407 => (
            "Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"moat\"\r\n",
        ),
        502 => ("Bad Gateway", ""),
        _ => ("Service Unavailable", ""),
    };
    // The message may quote the request; no control byte of it is echoed.
    let message: String = message
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let body = format!("moat proxy: {message}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\n{extra}Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
