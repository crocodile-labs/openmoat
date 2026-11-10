//! One HTTPS `POST` with a JSON body, over the TLS stack the proxy uses
//! (rustls with the system's roots) and `std::net`: what the Telegram adapter
//! needs, and no more. Errors never name the request path, which holds the
//! bot's token.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// The most a response may hold.
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A client for one host, verified against the system's roots.
pub struct Client {
    host: &'static str,
    config: Arc<ClientConfig>,
}

impl Client {
    pub fn new(host: &'static str) -> Result<Self> {
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
            host,
            config: Arc::new(config),
        })
    }

    /// `POST path` with `body` as JSON, waiting up to `timeout` for the
    /// answer; the response body, whatever its status.
    pub fn post(&self, path: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let host = self.host;
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
        let name = ServerName::try_from(host).context("server name")?;
        let conn = ClientConnection::new(self.config.clone(), name)
            .with_context(|| format!("starting TLS with {host}"))?;
        let mut stream = StreamOwned::new(conn, sock);
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: openmoat\r\nContent-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .with_context(|| format!("sending to {host}"))?;
        let mut raw = Vec::new();
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
        body_of(&raw).with_context(|| format!("reading the answer of {host}"))
    }
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
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            bail!("the response was cut short");
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}
