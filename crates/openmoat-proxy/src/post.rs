//! One outbound HTTP `POST` for live audit delivery (ADR-081).
//!
//! The person names the endpoint in their delivery configuration, which the
//! agent cannot write; the request still keeps the proxy's own rules where
//! they apply:
//!
//! - `https` to any host, verified against the system's roots or a CA the
//!   person gives ([`Roots`]); plain `http` only to this machine's loopback
//!   addresses, where nothing crosses a network.
//! - Every resolved address is checked: link-local, cloud metadata and
//!   non-unicast addresses are refused whatever the configuration says, so a
//!   name pointed at the metadata service gets no audit log. Private and
//!   loopback addresses pass: a collector usually lives there.
//! - No redirect is followed, no proxy variable is read, and only the
//!   response's status line and headers are read, up to a limit.
//!
//! Plain `std::net` and rustls, one connection per request with deadlines,
//! as the rest of this crate.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::decide::{self, Forbidden};
use crate::tls::{Roots, TlsError};
use crate::upstream::Resolve;

/// The most bytes of a response head read before giving up on it.
const MAX_HEAD: usize = 16 * 1024;

/// The most response headers read.
const MAX_RESPONSE_HEADERS: usize = 64;

/// Why a request was not made or not answered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostError {
    /// The URL is not one this client sends to.
    #[error("{0}")]
    Url(String),
    /// A header name or value that would change the request's framing.
    #[error("header `{0}` has a character a header cannot carry")]
    Header(String),
    /// The name resolved to an address that is never reached.
    #[error("{host} resolves to {addr}, {}, which audit delivery never reaches", why.describe())]
    Address {
        /// The host named.
        host: String,
        /// The address refused.
        addr: IpAddr,
        /// Why.
        why: Forbidden,
    },
    /// Plain `http` to an address that is not loopback.
    #[error("{host} resolves to {addr}, not a loopback address: use https")]
    PlainOffMachine {
        /// The host named.
        host: String,
        /// The address that is not loopback.
        addr: IpAddr,
    },
    /// Nothing answered.
    #[error("cannot reach {0}")]
    Unreachable(String),
    /// TLS could not be set up or failed.
    #[error("TLS: {0}")]
    Tls(String),
    /// Reading or writing failed, or timed out.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The answer is not an HTTP/1.x response head within the limits.
    #[error("the answer is not an HTTP response: {0}")]
    Response(String),
}

/// `http` or `https`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Loopback only.
    Http,
    /// TLS, verified.
    Https,
}

/// Where a request goes: scheme, host, port and the path with its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// The host as written, without brackets for an IPv6 literal.
    pub host: String,
    /// The port, the scheme's default when none is written.
    pub port: u16,
    /// Path and query, `/` when none is written.
    pub path: String,
}

impl Endpoint {
    /// Read `url`. Refused: another scheme, user information, a fragment,
    /// whitespace or control characters, and `http` to a name other than
    /// `localhost` or a loopback literal.
    pub fn parse(url: &str) -> Result<Self, PostError> {
        let bad = |why: &str| PostError::Url(format!("`{url}`: {why}"));
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(bad("a URL has no spaces or control characters"));
        }
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(bad("only https:// (or http:// to this machine) is sent to"));
        };
        if rest.contains('#') {
            return Err(bad("a fragment is never sent"));
        }
        let (authority, path) = match rest.find(['/', '?']) {
            Some(at) if rest[at..].starts_with('/') => (&rest[..at], rest[at..].to_owned()),
            Some(at) => (&rest[..at], format!("/{}", &rest[at..])),
            None => (rest, "/".to_owned()),
        };
        if authority.contains('@') {
            return Err(bad("credentials go in a header, never in the URL"));
        }
        let default = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        let (host, port) = split_port(authority, default).ok_or_else(|| bad("no valid host"))?;
        if decide::metadata_name(host.trim_end_matches('.')) {
            return Err(bad("a cloud metadata service is never sent to"));
        }
        let endpoint = Self {
            scheme,
            host,
            port,
            path,
        };
        if scheme == Scheme::Http && !endpoint.names_loopback() {
            return Err(bad(
                "plain http goes only to this machine (localhost, 127.0.0.1, [::1]); use https",
            ));
        }
        Ok(endpoint)
    }

    fn names_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// The `Host` header's value.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn split_port(authority: &str, default: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        host.parse::<std::net::Ipv6Addr>().ok()?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':');
    if host.is_empty() || !host.chars().all(valid) {
        return None;
    }
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0)?,
        None => default,
    };
    Some((host.to_ascii_lowercase(), port))
}

/// What the endpoint answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status code.
    pub status: u16,
    /// `Retry-After` in seconds, when it gave one in that form.
    pub retry_after_s: Option<u64>,
}

impl Answer {
    /// A `2xx` status.
    #[must_use]
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// A status that asks to try again later: `408`, `429`, any `5xx` but
    /// `501` and `505`. The OTLP specification names `429`, `502`, `503` and
    /// `504` as retryable; webhooks commonly use the others too.
    #[must_use]
    pub fn retryable(&self) -> bool {
        matches!(self.status, 408 | 429)
            || (500..600).contains(&self.status) && !matches!(self.status, 501 | 505)
    }
}

/// Sends requests: the TLS configuration and the resolver, kept for every
/// request of one delivery run.
pub struct Poster {
    tls: Arc<ClientConfig>,
    resolver: Box<dyn Resolve>,
}

impl std::fmt::Debug for Poster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poster").finish_non_exhaustive()
    }
}

impl Poster {
    /// A client verifying servers against `roots`, resolving with `resolver`.
    pub fn new(roots: &Roots, resolver: Box<dyn Resolve>) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Ok(Self {
            tls: Arc::new(crate::tls::upstream_config(roots, &provider)?),
            resolver,
        })
    }

    /// `POST` `body` to `endpoint` with `headers` (besides `Host`,
    /// `Content-Length` and `Connection: close`), each step within
    /// `timeout`, and read the answer's head.
    pub fn post(
        &self,
        endpoint: &Endpoint,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<Answer, PostError> {
        let request = request_head(endpoint, headers, body.len())?;
        let tcp = self.connect(endpoint, timeout)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        match endpoint.scheme {
            Scheme::Http => exchange(tcp, &request, body),
            Scheme::Https => {
                let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| {
                    PostError::Url(format!("{} is not a server name", endpoint.host))
                })?;
                let conn = ClientConnection::new(self.tls.clone(), name)
                    .map_err(|e| PostError::Tls(e.to_string()))?;
                exchange(StreamOwned::new(conn, tcp), &request, body)
            }
        }
    }

    fn connect(&self, endpoint: &Endpoint, timeout: Duration) -> Result<TcpStream, PostError> {
        let host = &endpoint.host;
        let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, endpoint.port)],
            Err(_) => self
                .resolver
                .resolve(host, endpoint.port)
                .map_err(|e| PostError::Unreachable(format!("{host}: {e}")))?,
        };
        if addrs.is_empty() {
            return Err(PostError::Unreachable(format!("{host}: no addresses")));
        }
        // One bad address refuses the name, as in the proxy.
        for addr in &addrs {
            check_address(endpoint, addr.ip())?;
        }
        let mut last = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        Err(PostError::Unreachable(match last {
            Some(e) => format!("{host}:{}: {e}", endpoint.port),
            None => format!("{host}:{}", endpoint.port),
        }))
    }
}

/// Refuse an address audit delivery never reaches, and plain http off the
/// machine.
fn check_address(endpoint: &Endpoint, ip: IpAddr) -> Result<(), PostError> {
    match decide::forbidden(ip) {
        Some(why @ (Forbidden::LinkLocal | Forbidden::Metadata | Forbidden::NotUnicast)) => {
            return Err(PostError::Address {
                host: endpoint.host.clone(),
                addr: ip,
                why,
            });
        }
        Some(Forbidden::Loopback) => return Ok(()),
        _ => {}
    }
    if endpoint.scheme == Scheme::Http {
        return Err(PostError::PlainOffMachine {
            host: endpoint.host.clone(),
            addr: ip,
        });
    }
    Ok(())
}

/// The request line and headers, refusing a header that would change framing.
fn request_head(
    endpoint: &Endpoint,
    headers: &[(&str, &str)],
    length: usize,
) -> Result<Vec<u8>, PostError> {
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {length}\r\nConnection: close\r\n",
        endpoint.path,
        endpoint.authority()
    );
    for (name, value) in headers {
        let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
        let framing = ["host", "content-length", "connection", "transfer-encoding"];
        if name.is_empty()
            || !name.chars().all(token)
            || framing.iter().any(|f| name.eq_ignore_ascii_case(f))
            || value.chars().any(|c| c.is_control() && c != '\t')
        {
            return Err(PostError::Header((*name).to_owned()));
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(head.into_bytes())
}

/// Write the request and read the answer's head from `stream`.
pub(crate) fn exchange(
    mut stream: impl Read + Write,
    head: &[u8],
    body: &[u8],
) -> Result<Answer, PostError> {
    stream.write_all(head)?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(answer) = parse_head(&buf)? {
            return Ok(answer);
        }
        if buf.len() >= MAX_HEAD {
            return Err(PostError::Response(format!(
                "no end of head in {MAX_HEAD} bytes"
            )));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(PostError::Response(
                "closed before the head ended".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(buf: &[u8]) -> Result<Option<Answer>, PostError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(_)) => {
            let status = response
                .code
                .ok_or_else(|| PostError::Response("no status".to_owned()))?;
            let retry_after_s = response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("retry-after"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            Ok(Some(Answer {
                status,
                retry_after_s,
            }))
        }
        Err(e) => Err(PostError::Response(e.to_string())),
    }
}

#[cfg(test)]
mod tests;
