//! One remote MCP server over Streamable HTTP: each message the relay passed
//! on is one `POST`, and the server's answer (one JSON message, or a stream
//! of events) comes back as the messages the relay then checks (ADR-127).
//!
//! What crosses the network is OpenMoat's own request: the agent's bytes are
//! the JSON body the relay already checked, and every header is written
//! here from that body and the record a person made (`Authorization`,
//! `MCP-Protocol-Version`, `Mcp-Session-Id`, and for MCP 2026-07-28 `Mcp-Method`
//! and `Mcp-Name`). No response header reaches the agent.
//!
//! Every connection goes through the egress proxy's own connect
//! ([`openmoat_proxy::connect`]): the name is resolved once, every address is
//! checked, and the connection is made to one of exactly those addresses, so a
//! name cannot be pointed at a local or metadata service between the check
//! and the connection. No redirect is followed. `https` is verified against
//! the system's roots.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{CompiledPolicy, EvalContext, Policy};
use openmoat_proxy::{Endpoint, Resolve, Scheme};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use zeroize::Zeroizing;

use super::sse::{self, Kind};

/// The most a response may hold.
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The most response headers read.
const MAX_HEADERS: usize = 64;
/// The MCP revision whose requests name their method and target in headers.
const REVISION_2026: &str = "2026-07-28";

/// An answer: its status, headers and body.
pub struct Reply {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: Zeroizing<Vec<u8>>,
}

impl Reply {
    /// The first header called `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The connection settings of one remote server, shared by every request.
pub struct Transport {
    endpoint: Endpoint,
    token: Option<Zeroizing<String>>,
    tls: Arc<ClientConfig>,
    addresses: Policy,
    ctx: EvalContext,
    resolver: Box<dyn Resolve>,
    timeout: Duration,
    session: Mutex<Option<String>>,
    version: Mutex<Option<String>>,
}

impl Transport {
    /// A transport to `endpoint` adding `token`, whose addresses `policy`'s
    /// address rules decide ([`openmoat_proxy::address_policy`]).
    pub fn new(
        endpoint: Endpoint,
        token: Option<Zeroizing<String>>,
        policy: &Policy,
        ctx: EvalContext,
        resolver: Box<dyn Resolve>,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            endpoint,
            token,
            tls: tls_config()?,
            addresses: openmoat_proxy::address_policy(policy),
            ctx,
            resolver,
            timeout,
            session: Mutex::new(None),
            version: Mutex::new(None),
        })
    }

    /// Send `message`, one line the relay passed on, and the messages the
    /// server answered it with (none for a notification or a response).
    pub fn send(&self, message: &str) -> Result<Vec<String>> {
        let parsed: Value = serde_json::from_str(message).context("reading the message")?;
        let method = parsed.get("method").and_then(Value::as_str);
        let id = parsed.get("id").filter(|_| method.is_some()).cloned();
        let headers = self.headers(&parsed, method);
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let path = self.endpoint.path.clone();
        let reply = self.exchange(
            &self.endpoint,
            "POST",
            &path,
            &pairs,
            message.as_bytes(),
            id.as_ref(),
        )?;
        match reply.status {
            202 => Ok(Vec::new()),
            200..=299 => {
                let messages = messages(&reply)?;
                if method == Some("initialize") {
                    self.remember(&reply, &messages);
                }
                Ok(messages)
            }
            300..=399 => bail!("the server answered with a redirect, which OpenMoat never follows"),
            401 | 403 => bail!("{}", super::discovery::sign_in_needed(&reply)),
            404 if self.session().is_some() => {
                *self.session.lock().unwrap_or_else(PoisonError::into_inner) = None;
                bail!("the server ended the session; the agent must connect again")
            }
            status => bail!("the server answered HTTP {status}"),
        }
    }

    /// `GET` `endpoint` without the token: metadata a person's sign-in reads
    /// (ADR-127 §3), checked as every request is.
    pub fn get(&self, endpoint: &Endpoint) -> Result<Reply> {
        let accept = [("Accept", "application/json")];
        self.exchange(endpoint, "GET", &endpoint.path, &accept, &[], None)
    }

    fn session(&self) -> Option<String> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The headers of a `POST` of `parsed`.
    fn headers(&self, parsed: &Value, method: Option<&str>) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("Accept", "application/json, text/event-stream".to_owned()),
            ("Content-Type", "application/json".to_owned()),
        ];
        let named = parsed
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let version = named.clone().or_else(|| {
            self.version
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        });
        if let Some(version) = version.filter(|v| token_value(v)) {
            out.push(("MCP-Protocol-Version", version));
        }
        if let Some(session) = self.session() {
            out.push(("Mcp-Session-Id", session));
        }
        if named.as_deref() == Some(REVISION_2026)
            && let Some(method) = method.filter(|m| token_value(m))
        {
            out.push(("Mcp-Method", method.to_owned()));
            let target = parsed
                .pointer("/params/name")
                .or_else(|| parsed.pointer("/params/uri"))
                .and_then(Value::as_str)
                .filter(|t| token_value(t));
            if let Some(target) = target {
                out.push(("Mcp-Name", target.to_owned()));
            }
        }
        if let Some(token) = &self.token {
            out.push(("Authorization", format!("Bearer {}", token.as_str())));
        }
        out
    }

    /// Keep the session id and the protocol version an `initialize` answer
    /// gave.
    fn remember(&self, reply: &Reply, messages: &[String]) {
        if let Some(session) = reply.header("mcp-session-id").filter(|s| token_value(s)) {
            *self.session.lock().unwrap_or_else(PoisonError::into_inner) = Some(session.to_owned());
        }
        let version = messages.iter().find_map(|m| {
            let v: Value = serde_json::from_str(m).ok()?;
            v.pointer("/result/protocolVersion")?
                .as_str()
                .map(ToOwned::to_owned)
        });
        if let Some(version) = version {
            *self.version.lock().unwrap_or_else(PoisonError::into_inner) = Some(version);
        }
    }

    /// One request and its answer, over a connection made through the egress
    /// proxy's checks. With `until`, an event stream is read only until the
    /// response to that request id arrives.
    fn exchange(
        &self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        until: Option<&Value>,
    ) -> Result<Reply> {
        let head = request_head(endpoint, method, path, headers, body.len())?;
        let tcp = self.connect(endpoint)?;
        tcp.set_read_timeout(Some(self.timeout))
            .and_then(|()| tcp.set_write_timeout(Some(self.timeout)))
            .context("setting up the connection")?;
        match endpoint.scheme {
            Scheme::Http => read_reply(tcp, &head, body, until),
            Scheme::Https => {
                let name = ServerName::try_from(endpoint.host.clone())
                    .with_context(|| format!("{} is not a server name", endpoint.host))?;
                let conn = ClientConnection::new(self.tls.clone(), name)
                    .with_context(|| format!("starting TLS with {}", endpoint.host))?;
                read_reply(StreamOwned::new(conn, tcp), &head, body, until)
            }
        }
    }

    fn connect(&self, endpoint: &Endpoint) -> Result<std::net::TcpStream> {
        let addresses = CompiledPolicy::compile(&self.addresses, &self.ctx)
            .context("compiling the policy's address rules")?;
        // A loopback address is reached only when written as one and named
        // by an allow rule with its port: a person's local server.
        let loopback: Vec<SocketAddr> = endpoint
            .host
            .parse::<IpAddr>()
            .ok()
            .filter(IpAddr::is_loopback)
            .map(|ip| SocketAddr::new(ip, endpoint.port))
            .filter(|addr| openmoat_proxy::address_named_on(&addresses, *addr))
            .into_iter()
            .collect();
        openmoat_proxy::connect(
            &*self.resolver,
            &endpoint.host,
            endpoint.port,
            &addresses,
            &loopback,
            CONNECT_TIMEOUT,
        )
        .map_err(|refusal| {
            let decision = refusal.decision(&endpoint.host);
            anyhow::Error::msg(decision.reasons.join("; "))
        })
    }
}

/// The messages a successful answer carries.
fn messages(reply: &Reply) -> Result<Vec<String>> {
    let kind = reply.header("content-type").and_then(Kind::of);
    match kind {
        Some(Kind::Json) => Ok(vec![String::from_utf8_lossy(&reply.body).trim().to_owned()]),
        Some(Kind::Events) => Ok(sse::events(&reply.body)),
        None if reply.body.iter().all(u8::is_ascii_whitespace) => Ok(Vec::new()),
        None => bail!("the server answered with a body that is neither JSON nor an event stream"),
    }
}

/// A header value OpenMoat writes: visible ASCII only, so nothing the agent
/// chose can end a header or start another.
fn token_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("setting up TLS")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The request line and headers.
fn request_head(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let host = if endpoint.host.contains(':') {
        format!("[{}]", endpoint.host)
    } else {
        endpoint.host.clone()
    };
    let default = match endpoint.scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let authority = if endpoint.port == default {
        host
    } else {
        format!("{host}:{}", endpoint.port)
    };
    let mut head = Zeroizing::new(format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: openmoat\r\nConnection: close\r\n"
    ));
    if method != "GET" {
        head.push_str("Content-Length: ");
        head.push_str(&length.to_string());
        head.push_str("\r\n");
    }
    for (name, value) in headers {
        if value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            bail!("header `{name}` has a character a header cannot carry");
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(Zeroizing::new(head.as_bytes().to_vec()))
}

/// Write the request to `stream` and read the answer: to its end, or for an
/// event stream with `until`, until the response to that id.
pub(super) fn read_reply(
    mut stream: impl Read + Write,
    head: &[u8],
    body: &[u8],
    until: Option<&Value>,
) -> Result<Reply> {
    stream
        .write_all(head)
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .context("sending the request")?;
    let mut raw = Zeroizing::new(Vec::new());
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            // A server that closes without TLS's close alert: the framing
            // checks below tell a cut answer from a whole one.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e).context("reading the answer"),
        };
        if n == 0 {
            let (reply, framed) = parse(&raw)?;
            if framed == Framed::Short {
                bail!("the answer was cut short");
            }
            return Ok(reply);
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_RESPONSE {
            bail!(
                "the answer is larger than {} MiB",
                MAX_RESPONSE / (1024 * 1024)
            );
        }
        if let Ok((reply, framed)) = parse(&raw)
            && (framed == Framed::Whole || answered(&reply, until))
        {
            return Ok(reply);
        }
    }
}

/// How much of a body arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framed {
    /// Its length or last chunk arrived.
    Whole,
    /// Its length or last chunk is still to come.
    Short,
    /// It ends when the connection does.
    ToClose,
}

/// Whether `reply`, read so far, is an event stream holding the response to
/// `until`: the server need not close it then.
fn answered(reply: &Reply, until: Option<&Value>) -> bool {
    let streaming = reply.header("content-type").and_then(Kind::of) == Some(Kind::Events);
    let (true, Some(id)) = (streaming, until) else {
        return false;
    };
    sse::events(&reply.body).iter().any(|event| {
        serde_json::from_str::<Value>(event).is_ok_and(|v| {
            v.get("id") == Some(id) && (v.get("result").is_some() || v.get("error").is_some())
        })
    })
}

fn chunked(reply: &Reply) -> bool {
    reply
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().ends_with("chunked"))
}

/// The answer in `raw` so far, with as much of its body as arrived and how
/// much that is.
fn parse(raw: &[u8]) -> Result<(Reply, Framed)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(start) = response.parse(raw)? else {
        bail!("the answer ended in its head");
    };
    let status = response.code.context("the answer has no status")?;
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).trim().to_owned(),
            )
        })
        .collect();
    let mut reply = Reply {
        status,
        headers,
        body: Zeroizing::new(Vec::new()),
    };
    let rest = &raw[start..];
    let (body, framed) = if matches!(status, 204 | 304) || (100..200).contains(&status) {
        (Vec::new(), Framed::Whole)
    } else if chunked(&reply) {
        dechunk(rest)?
    } else if let Some(length) = reply.header("content-length") {
        let length: usize = length.parse().context("a bad Content-Length")?;
        if length > MAX_RESPONSE {
            bail!("the answer is larger than any answer OpenMoat reads");
        }
        match rest.get(..length) {
            Some(body) => (body.to_vec(), Framed::Whole),
            None => (rest.to_vec(), Framed::Short),
        }
    } else {
        (rest.to_vec(), Framed::ToClose)
    };
    reply.body = Zeroizing::new(body);
    Ok((reply, framed))
}

/// A chunked body: the chunks that arrived whole, and whether the last one
/// did.
fn dechunk(mut rest: &[u8]) -> Result<(Vec<u8>, Framed)> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok((out, Framed::Short));
        };
        let size_text = std::str::from_utf8(&rest[..line_end]).context("a bad chunk size")?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).context("a bad chunk size")?;
        // A size no answer OpenMoat reads can hold is refused, before any
        // arithmetic on it can overflow.
        if size > MAX_RESPONSE {
            bail!("a chunk larger than any answer OpenMoat reads");
        }
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok((out, Framed::Whole));
        }
        let Some(chunk) = rest.get(..size) else {
            return Ok((out, Framed::Short));
        };
        out.extend_from_slice(chunk);
        let Some(after) = rest.get(size + 2..) else {
            return Ok((out, Framed::Short));
        };
        rest = after;
    }
}
