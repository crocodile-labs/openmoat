//! A response and the headers every one carries: no caching, no framing, no
//! referrer, no sniffing, a Content Security Policy that lets the page load
//! nothing but this server's stylesheet and run nothing, no CORS header (so
//! no other site's script can read a response), and no cookie.

use std::io::{self, Write};

/// Every response's security headers.
const HEADERS: &str = "Cache-Control: no-store\r\n\
    Content-Security-Policy: default-src 'none'; style-src 'self'; base-uri 'none'; \
    form-action 'none'; frame-ancestors 'none'\r\n\
    X-Content-Type-Options: nosniff\r\n\
    Referrer-Policy: no-referrer\r\n\
    X-Frame-Options: DENY\r\n\
    Cross-Origin-Opener-Policy: same-origin\r\n\
    Cross-Origin-Resource-Policy: same-origin\r\n\
    Connection: close\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// A header only some statuses carry (`Allow`, `WWW-Authenticate`).
    extra: Option<&'static str>,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        let extra = match status {
            401 => Some("WWW-Authenticate: Bearer\r\n"),
            405 => Some("Allow: GET\r\n"),
            _ => None,
        };
        Self {
            status,
            content_type,
            body: body.into(),
            extra,
        }
    }

    pub fn text(status: u16, text: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", format!("{text}\n"))
    }

    pub fn unauthorized() -> Self {
        Self::text(
            401,
            "this needs the token from the link `openmoat serve` printed",
        )
    }

    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{HEADERS}{}\r\n",
            self.status,
            reason(self.status),
            self.content_type,
            self.body.len(),
            self.extra.unwrap_or_default(),
        )?;
        out.write_all(&self.body)?;
        out.flush()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    }
}
