//! A request read inside a terminated tunnel (ADR-043): origin form
//! (`GET /path HTTP/1.1`), for the one host the tunnel was opened to.
//!
//! The same rules as a plain-HTTP request: framing made unambiguous,
//! hop-by-hop headers removed, `Connection: close` added, so the upstream
//! answers this request alone. On top of them:
//!
//! - the target is a path: the absolute form could name another host;
//! - `Host` must name the tunnel's host and port, once;
//! - `Accept-Encoding` becomes `identity`, so the answer can be read for the
//!   secret's value before it reaches the agent;
//! - `Expect: 100-continue` is answered by the proxy and not forwarded, since
//!   the proxy reads one direction at a time.

use zeroize::Zeroizing;

use super::{HOP_BY_HOP, MAX_HEADERS, RequestError, authority, check_framing};

/// One request head from inside a terminated tunnel, rewritten for the upstream.
pub(crate) struct Inner {
    /// The method, as sent.
    pub(crate) method: String,
    /// The head to send upstream. It may hold a placeholder, never a value
    /// yet; zeroed on drop all the same, as it is copied with the value in.
    pub(crate) head: Zeroizing<Vec<u8>>,
    /// Bytes of the input the head occupied.
    pub(crate) head_len: usize,
    /// The client sent `Expect: 100-continue` and waits for a `100` first.
    pub(crate) expects_continue: bool,
    /// How its body ends, read from `head` (before a value goes in).
    pub(crate) framing: crate::body::Framing,
}

/// Parse one request head from the start of `buf`, sent inside a tunnel to
/// `host` on `port`. `Ok(None)`: not complete yet.
pub(crate) fn parse(buf: &[u8], host: &str, port: u16) -> Result<Option<Inner>, RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(RequestError::Malformed(e.to_string())),
    };
    let (Some(method), Some(target), Some(version)) = (req.method, req.path, req.version) else {
        return Err(RequestError::Malformed(
            "incomplete request line".to_owned(),
        ));
    };
    if method == "CONNECT" || !target.starts_with('/') {
        return Err(RequestError::Unsupported(
            "inside a tunnel only a path is requested (`GET /path`), not another host",
        ));
    }
    check_framing(version, req.headers)?;
    let mut connection_tokens: Vec<String> = Vec::new();
    for h in req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
    {
        let value = String::from_utf8_lossy(h.value);
        connection_tokens.extend(value.split(',').map(|t| t.trim().to_ascii_lowercase()));
    }
    let mut head = Zeroizing::new(format!("{method} {target} HTTP/1.{version}\r\n").into_bytes());
    let mut hosts = 0;
    let mut expects_continue = false;
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) || connection_tokens.contains(&name) {
            continue;
        }
        match name.as_str() {
            "host" => {
                let named = std::str::from_utf8(h.value)
                    .ok()
                    .and_then(|v| authority(v.trim(), Some(443)).ok());
                if named != Some((host.to_owned(), port)) {
                    return Err(RequestError::Unsupported(
                        "the Host header does not name the host the tunnel was opened to",
                    ));
                }
                hosts += 1;
            }
            "expect" => {
                if !h.value.eq_ignore_ascii_case(b"100-continue") {
                    return Err(RequestError::Unsupported(
                        "an `Expect` other than `100-continue`",
                    ));
                }
                expects_continue = true;
                continue;
            }
            "accept-encoding" => continue,
            _ => {}
        }
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }
    if hosts != 1 {
        return Err(RequestError::Unsupported(
            "a request inside a tunnel needs exactly one Host header",
        ));
    }
    head.extend_from_slice(b"Accept-Encoding: identity\r\nConnection: close\r\n\r\n");
    let framing = crate::body::framing(&head);
    Ok(Some(Inner {
        method: method.to_owned(),
        head,
        head_len,
        expects_continue,
        framing,
    }))
}
