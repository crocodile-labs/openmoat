//! One request as `openmoat serve` reads it, and the checks every request
//! passes before anything is read for it: the `Host` header names this
//! server on loopback (DNS rebinding), a browser's `Origin` and
//! `Sec-Fetch-Site` say this site or none (another page's requests), the
//! method is `GET` with no body, and the run's token is there.

use super::address;
use super::response::Response;
use super::token::Token;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// The longest request head read; a longer one gets 431.
pub const MAX_HEAD: usize = 8 * 1024;

/// The most headers a request may have.
const MAX_HEADERS: usize = 48;

/// A parsed request head.
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The query's parameters, percent-decoded, each name once.
    pub query: Vec<(String, String)>,
    host: Option<String>,
    origin: Option<String>,
    fetch_site: Option<String>,
    authorization: Option<String>,
    has_body: bool,
}

impl Request {
    /// The value of query parameter `name`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse the request head at the start of `buf`: `Ok(None)` while it is
/// incomplete, an error response when it is malformed.
pub fn parse(buf: &[u8]) -> Result<Option<Request>, Response> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(Response::text(400, "malformed request")),
    }
    let (Some(method), Some(target)) = (req.method, req.path) else {
        return Err(Response::text(400, "malformed request"));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut out = Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: parse_query(query).ok_or_else(|| Response::text(400, "malformed query"))?,
        ..Request::default()
    };
    for header in req.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Response::text(400, "a header that is not UTF-8"))?
            .trim()
            .to_owned();
        let slot = match header.name.to_ascii_lowercase().as_str() {
            "host" => &mut out.host,
            "origin" => &mut out.origin,
            "sec-fetch-site" => &mut out.fetch_site,
            "authorization" => &mut out.authorization,
            "content-length" => {
                out.has_body |= value != "0";
                continue;
            }
            "transfer-encoding" => {
                out.has_body = true;
                continue;
            }
            _ => continue,
        };
        // Two of one of these could be read two ways; refuse instead.
        if slot.replace(value).is_some() {
            return Err(Response::text(400, "a header given twice"));
        }
    }
    Ok(Some(out))
}

/// Refuse `req` unless it is a `GET` with no body, for this server by a
/// loopback name on `port`, not from another site, and carrying `token`.
pub fn check(req: &Request, port: u16, token: &Token) -> Result<(), Response> {
    let names = address::host_names(port);
    let ours = |host: &str| names.iter().any(|n| n.eq_ignore_ascii_case(host));
    if !req.host.as_deref().is_some_and(ours) {
        return Err(Response::text(
            403,
            "the Host header does not name this server on 127.0.0.1",
        ));
    }
    if let Some(origin) = &req.origin {
        let host = origin.strip_prefix("http://").unwrap_or_default();
        if !ours(host) {
            return Err(Response::text(403, "a request from another site"));
        }
    }
    if let Some(site) = &req.fetch_site
        && !matches!(site.as_str(), "same-origin" | "none")
    {
        return Err(Response::text(403, "a request from another site"));
    }
    if req.method != "GET" {
        return Err(Response::text(405, "read-only: only GET is served"));
    }
    if req.has_body {
        return Err(Response::text(400, "a GET with a body"));
    }
    let bearer = req
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "));
    let given = match (bearer, req.param("token")) {
        (Some(token), None) | (None, Some(token)) => token,
        (Some(_), Some(_)) => return Err(Response::text(400, "the token given twice")),
        (None, None) => return Err(Response::unauthorized()),
    };
    if token.matches(given) {
        Ok(())
    } else {
        Err(Response::unauthorized())
    }
}

/// `a=1&b=x%20y` as name and value pairs, `+` as a space; `None` on bad
/// percent-encoding, text that is not UTF-8, or a name given twice.
fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (name, value) = (decode(name)?, decode(value)?);
        if out.iter().any(|(n, _)| *n == name) {
            return None;
        }
        out.push((name, value));
    }
    Some(out)
}

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let &[high, low] = bytes.get(i + 1..i + 3)? else {
                    return None;
                };
                let [high, low] = [high, low].map(|c| char::from(c).to_digit(16));
                out.push(u8::try_from(high? * 16 + low?).ok()?);
                i += 2;
            }
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// `text` percent-encoded for a query value: everything but RFC 3986's
/// unreserved characters.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[usize::from(b >> 4)]));
            out.push(char::from(HEX_UPPER[usize::from(b & 0xf)]));
        }
    }
    out
}
