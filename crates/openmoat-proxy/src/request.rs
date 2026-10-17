//! The request head a client sends the proxy: `CONNECT host:port` or one
//! absolute-form plain-HTTP request (`GET http://host/path HTTP/1.1`).
//!
//! Hosts come out in the form openmoat-core's net rules match: lowercase, without
//! a trailing dot or IPv6 brackets, IP literals in their canonical spelling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most headers one request head may carry.
pub const MAX_HEADERS: usize = 64;

/// Headers that describe one connection, not the request (RFC 9110 §7.6.1),
/// plus the proxy credentials no upstream should see. `Transfer-Encoding` is
/// kept: the body is relayed byte for byte, so its framing must arrive intact.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// What the client asked the proxy to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `CONNECT host:port`: a tunnel, checked by the TLS SNI it then carries.
    Connect {
        /// Normalised host.
        host: String,
        /// Port; never 0.
        port: u16,
    },
    /// One plain-HTTP request, rewritten for the upstream.
    Http {
        /// Normalised host from the absolute-form target.
        host: String,
        /// Port; 80 when the target names none.
        port: u16,
        /// The head to send upstream: origin-form request line, hop-by-hop
        /// headers removed, `Host` present and `Connection: close` added.
        head: Vec<u8>,
    },
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, as sent (`CONNECT`, `GET`, …).
    pub method: String,
    /// Where the request goes.
    pub target: Target,
    /// Bytes of the input the head occupied; what follows is body or tunnel data.
    pub head_len: usize,
}

impl Request {
    /// The target host.
    #[must_use]
    pub fn host(&self) -> &str {
        match &self.target {
            Target::Connect { host, .. } | Target::Http { host, .. } => host,
        }
    }

    /// The target port.
    #[must_use]
    pub fn port(&self) -> u16 {
        match &self.target {
            Target::Connect { port, .. } | Target::Http { port, .. } => *port,
        }
    }
}

/// Why a request head is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// Not HTTP/1.x, or a syntax error `httparse` reports.
    #[error("malformed request: {0}")]
    Malformed(String),
    /// A well-formed request the proxy does not serve.
    #[error("{0}")]
    Unsupported(&'static str),
}

/// Parse one request head from the start of `buf`. `Ok(None)` means the head is
/// not complete yet; the caller bounds how much it reads.
pub fn parse(buf: &[u8]) -> Result<Option<Request>, RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(RequestError::Malformed(e.to_string())),
    };
    let (Some(method), Some(raw_target), Some(version)) = (req.method, req.path, req.version)
    else {
        return Err(RequestError::Malformed(
            "incomplete request line".to_owned(),
        ));
    };
    let target = if method == "CONNECT" {
        let (host, port) = authority(raw_target, None)?;
        Target::Connect { host, port }
    } else {
        http_target(method, raw_target, version, req.headers)?
    };
    Ok(Some(Request {
        method: method.to_owned(),
        target,
        head_len,
    }))
}

fn http_target(
    method: &str,
    raw_target: &str,
    version: u8,
    headers: &[httparse::Header<'_>],
) -> Result<Target, RequestError> {
    let Some((scheme, rest)) = raw_target.split_once("://") else {
        return Err(RequestError::Unsupported(
            "only absolute-form requests (http://host/path) are proxied",
        ));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(RequestError::Unsupported(
            "only http:// is forwarded; use CONNECT for https",
        ));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (raw_authority, path) = rest.split_at(end);
    let path = path.split('#').next().unwrap_or_default();
    let (host, port) = authority(raw_authority, Some(80))?;
    check_framing(headers)?;

    let mut connection_tokens: Vec<String> = Vec::new();
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
    {
        let value = String::from_utf8_lossy(h.value);
        connection_tokens.extend(value.split(',').map(|t| t.trim().to_ascii_lowercase()));
    }
    let slash = if path.starts_with('/') { "" } else { "/" };
    let mut head = format!("{method} {slash}{path} HTTP/1.{version}\r\n").into_bytes();
    let mut has_host = false;
    for h in headers {
        let name = h.name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) || connection_tokens.contains(&name) {
            continue;
        }
        if name == "host" {
            if has_host || host_header(h.value) != Some((host.clone(), port)) {
                return Err(RequestError::Unsupported(
                    "Host header does not match the request target",
                ));
            }
            has_host = true;
        }
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }
    if !has_host {
        head.extend_from_slice(format!("Host: {raw_authority}\r\n").as_bytes());
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(Target::Http { host, port, head })
}

/// Refuse the framing ambiguities request smuggling relies on: both
/// `Content-Length` and `Transfer-Encoding`, repeated or list-form length,
/// or a `Transfer-Encoding` whose tokens are anything but a single `chunked`.
fn check_framing(headers: &[httparse::Header<'_>]) -> Result<(), RequestError> {
    const AMBIGUOUS: RequestError = RequestError::Unsupported(
        "ambiguous body framing (Content-Length with Transfer-Encoding, repeated, \
         list-form length, or a transfer coding other than chunked)",
    );
    let mut lengths: Vec<&[u8]> = Vec::new();
    let mut encodings: Vec<&[u8]> = Vec::new();
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            lengths.push(h.value);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            encodings.push(h.value);
        }
    }
    if lengths.len() > 1 || (!lengths.is_empty() && !encodings.is_empty()) {
        return Err(AMBIGUOUS);
    }
    if encodings.len() > 1 {
        return Err(AMBIGUOUS);
    }
    if let Some(bytes) = encodings.first() {
        let value = std::str::from_utf8(bytes).map_err(|_| AMBIGUOUS)?;
        let tokens: Vec<String> = value
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .collect();
        if tokens.as_slice() != ["chunked"] {
            return Err(AMBIGUOUS);
        }
    }
    if let Some(bytes) = lengths.first() {
        let value = std::str::from_utf8(bytes).map_err(|_| AMBIGUOUS)?;
        let trimmed = value.trim();
        // RFC 9112 §8.6: a `Content-Length` is one or more decimal digits.
        // The explicit all-ASCII-digit check rejects `+10`, `-10`, embedded
        // whitespace (`10 10`), hex (`0x0a`) and the list form (`10, 10`);
        // `u64::from_str` guards against overflow after that.
        let digits_only = !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit());
        if !digits_only || trimmed.parse::<u64>().is_err() {
            return Err(AMBIGUOUS);
        }
    }
    Ok(())
}

fn host_header(value: &[u8]) -> Option<(String, u16)> {
    authority(std::str::from_utf8(value).ok()?.trim(), Some(80)).ok()
}

/// `host[:port]` or `[v6][:port]`, with no userinfo. `default_port` is `None`
/// when a port is required (CONNECT).
fn authority(raw: &str, default_port: Option<u16>) -> Result<(String, u16), RequestError> {
    const BAD: RequestError = RequestError::Unsupported("invalid host or port in request target");
    if raw.contains('@') {
        return Err(RequestError::Unsupported(
            "credentials in the request target are refused",
        ));
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (v6, after) = rest.split_once(']').ok_or(BAD)?;
        let ip: Ipv6Addr = v6.parse().map_err(|_| BAD)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(BAD)?),
        };
        (ip.to_string(), port)
    } else {
        let (host, port) = match raw.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (raw, None),
        };
        (normalise_name(host).ok_or(BAD)?, port)
    };
    let port = match (port, default_port) {
        (Some(p), _) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or(BAD)?,
        (None, Some(d)) => d,
        (None, None) => return Err(BAD),
    };
    Ok((host, port))
}

/// A DNS name or IPv4 literal in canonical form; `None` when it is neither.
pub(crate) fn normalise_name(raw: &str) -> Option<String> {
    let name = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(ip).to_string());
    }
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    // No top-level domain is a number. A name whose last label is digits or
    // `0x…` is an address in another spelling (`1572394766`, `0x5d.0xb8.0xd7.0x0e`,
    // `0177.0.0.1`) that the system resolver turns into an IP, past rules that
    // name the address the usual way.
    let last = name.rsplit('.').next().unwrap_or_default();
    let numeric = last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x");
    (valid && !numeric).then_some(name)
}

#[cfg(test)]
mod tests;
