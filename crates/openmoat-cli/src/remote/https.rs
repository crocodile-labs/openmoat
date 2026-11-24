//! One HTTPS request at a time, over the TLS stack the proxy uses (rustls with
//! the system's roots) and `std::net`: the transport the channels under
//! `channels/` share, and that the proxy's minted secrets (ADR-118,
//! `secrets/mint.rs`) are made with, and no more. In `remote/` only a channel
//! calls it; the core does no network I/O. Errors never name the request
//! path or a header, which may hold a credential.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::Zeroizing;

/// The most a response may hold.
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A client for one host, verified against the system's roots.
pub struct Client {
    host: String,
    config: Arc<ClientConfig>,
}

/// One request: its method, path, extra headers, content type and body. The
/// headers and body may hold credentials, so they are zeroed when dropped and
/// never shown.
pub struct Request {
    pub method: &'static str,
    pub path: String,
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    pub content_type: &'static str,
    pub body: Zeroizing<Vec<u8>>,
}

/// A response: its status and body, zeroed when dropped.
pub struct Response {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

impl Client {
    pub fn new(host: &str) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if roots.is_empty() {
            bail!("no trusted root certificates were found on this system");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("setting up TLS")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            host: host.to_owned(),
            config: Arc::new(config),
        })
    }

    /// `POST path` with `body` as JSON, waiting up to `timeout` for the
    /// answer; the response body, whatever its status.
    pub fn post(&self, path: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let request = Request {
            method: "POST",
            path: path.to_owned(),
            headers: Vec::new(),
            content_type: "application/json",
            body: Zeroizing::new(body.to_vec()),
        };
        Ok(self.send(&request, timeout)?.body.to_vec())
    }

    /// Send `request`, waiting up to `timeout` for the answer.
    pub fn send(&self, request: &Request, timeout: Duration) -> Result<Response> {
        let host = self.host.as_str();
        let addr = (host, 443)
            .to_socket_addrs()
            .with_context(|| format!("looking up {host}"))?
            .next()
            .with_context(|| format!("{host} has no address"))?;
        let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .with_context(|| format!("connecting to {host}"))?;
        sock.set_read_timeout(Some(timeout))
            .and_then(|()| sock.set_write_timeout(Some(timeout)))
            .with_context(|| format!("setting up the connection to {host}"))?;
        let name = ServerName::try_from(host.to_owned()).context("server name")?;
        let conn = ClientConnection::new(self.config.clone(), name)
            .with_context(|| format!("starting TLS with {host}"))?;
        let mut stream = StreamOwned::new(conn, sock);
        let head = head(host, request);
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&request.body))
            .and_then(|()| stream.flush())
            .with_context(|| format!("sending to {host}"))?;
        let mut raw = Zeroizing::new(Vec::new());
        match std::io::Read::by_ref(&mut stream)
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut raw)
        {
            Ok(_) => {}
            // A server that closes without TLS's close alert: the length
            // checks below tell a cut response from a whole one.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => {}
            Err(e) => return Err(e).with_context(|| format!("reading the answer of {host}")),
        }
        if raw.len() as u64 > MAX_RESPONSE {
            bail!("the answer of {host} is too large");
        }
        let status = status_of(&raw).with_context(|| format!("reading the answer of {host}"))?;
        let body = body_of(&raw).with_context(|| format!("reading the answer of {host}"))?;
        Ok(Response {
            status,
            body: Zeroizing::new(body),
        })
    }
}

/// The head of `request` to `host`, as sent.
pub fn head(host: &str, request: &Request) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut head = Zeroizing::new(format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: openmoat\r\n",
        request.method, request.path
    ));
    for (name, value) in &request.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if request.method != "GET" {
        let _ = write!(
            head,
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            request.content_type,
            request.body.len()
        );
    }
    head.push_str("Connection: close\r\n\r\n");
    head
}

/// The status code of the HTTP/1.1 response `raw`.
pub fn status_of(raw: &[u8]) -> Result<u16> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(raw)?;
    response.code.context("the response has no status")
}

/// The body of the HTTP/1.1 response `raw`: by `Content-Length`, chunked, or
/// up to the end.
pub fn body_of(raw: &[u8]) -> Result<Vec<u8>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(start) = response.parse(raw)? else {
        bail!("the response ended in its head");
    };
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let rest = &raw[start..];
    if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        return chunked(rest);
    }
    if let Some(length) = header("content-length") {
        let length: usize = length.parse().context("a bad Content-Length")?;
        if rest.len() < length {
            bail!("the response was cut short");
        }
        return Ok(rest[..length].to_vec());
    }
    Ok(rest.to_vec())
}

fn chunked(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("a chunk without its size line")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).context("a bad chunk size")?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).context("a bad chunk size")?;
        // A size no response of MAX_RESPONSE bytes can hold is refused, before
        // any arithmetic on it can overflow.
        if !u64::try_from(size).is_ok_and(|s| s <= MAX_RESPONSE) {
            bail!("a chunk larger than any response OpenMoat reads");
        }
        rest = rest.get(line_end + 2..).unwrap_or_default();
        if size == 0 {
            return Ok(out);
        }
        let (Some(chunk), Some(after)) = (rest.get(..size), size.checked_add(2)) else {
            bail!("the response was cut short");
        };
        out.extend_from_slice(chunk);
        rest = rest.get(after..).context("the response was cut short")?;
    }
}

#[cfg(test)]
mod tests {
    use super::body_of;

    #[test]
    fn response_bodies_by_length_chunks_or_end() {
        let by_length = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}xx";
        assert_eq!(body_of(by_length).unwrap(), b"{}xx");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{\"\r\n3\r\nok\"\r\n0\r\n\r\n";
        assert_eq!(body_of(chunked).unwrap(), b"{\"ok\"");
        let to_end = b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}";
        assert_eq!(body_of(to_end).unwrap(), b"{\"ok\":true}");
        let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{}";
        assert!(body_of(cut).is_err());
        assert!(body_of(b"HTTP/1.1 200").is_err());
    }

    /// A chunk size near `usize::MAX` once made `size + 2` overflow (a panic
    /// in a debug build, a slice out of range in a release one); any size
    /// past the response limit is refused, as is a chunk cut short.
    #[test]
    fn chunk_sizes_past_the_limit_or_cut_short_are_errors() {
        let huge = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\nab\r\n0\r\n\r\n",
            usize::MAX
        );
        assert!(body_of(huge.as_bytes()).is_err());
        let over = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\nab\r\n0\r\n\r\n",
            super::MAX_RESPONSE + 1
        );
        assert!(body_of(over.as_bytes()).is_err());
        let short = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab";
        assert!(body_of(short).is_err());
        let no_crlf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab";
        assert!(body_of(no_crlf).is_err());
    }
}
