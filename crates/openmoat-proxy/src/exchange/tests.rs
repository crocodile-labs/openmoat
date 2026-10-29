//! A terminated tunnel end to end over socket pairs: an agent that trusts the
//! proxy's CA, the tunnel, and an upstream with a certificate of its own CA.
//! No port is bound, so these run where binding a socket is not allowed;
//! `tests/proxy/terminate.rs` runs the same path through a listening proxy.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use openmoat_core::{Decision, Policy, Verdict};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use zeroize::Zeroizing;

use super::{Tunnel, Wire};
use crate::broker::Broker;
use crate::server::Limits;
use crate::sni::{self, Hello};
use crate::tls::{Roots, Tls, new_ca};

mod attacks;

impl Wire for &UnixStream {
    fn timeouts(&self, read: Duration, write: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(read))?;
        self.set_write_timeout(Some(write))
    }

    fn close(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

impl Wire for UnixStream {
    fn timeouts(&self, read: Duration, write: Duration) -> std::io::Result<()> {
        <&UnixStream as Wire>::timeouts(&self, read, write)
    }

    fn close(&self) {
        <&UnixStream as Wire>::close(&self);
    }
}

/// Generated for the tests; no real secret is used.
const VALUE: &str = "fake-tls-brokered-3f9a8c21d7e46b05";
const OTHER_VALUE: &str = "fake-other-brokered-91c0e2b7a4";
const PLACEHOLDER: &str = "moat-secret:gh:placeholder";
const OTHER_PLACEHOLDER: &str = "moat-secret:other:placeholder";
const HOST: &str = "owner.test";
const WAIT: Duration = Duration::from_secs(5);
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";

fn broker() -> Broker {
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: gh\n    host: owner.test\n    header: Authorization\n    \
         source: { env: FAKE_GH }\n    tls: terminate\n    allow:\n      - GET /repos/**\n      \
         - HEAD /repos/**\n      - POST /repos/*/*/issues\n  - id: other\n    host: other.test\n    \
         header: X-Key\n    source: { env: FAKE_OTHER }\n",
    )
    .unwrap();
    let values = [VALUE, OTHER_VALUE];
    let held = policy
        .secrets
        .into_iter()
        .zip(values)
        .map(|(s, v)| (s, Zeroizing::new(v.to_owned())))
        .collect();
    Broker::new(held).unwrap()
}

/// A CA of the upstream's own and a server configuration for `name` it signed.
fn upstream_pki(name: &str) -> (String, Arc<ServerConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (ca.pem(), Arc::new(config))
}

struct Setup {
    tls: Tls,
    broker: Broker,
    /// The proxy's CA, which the agent trusts.
    agent_trusts: String,
    upstream: Arc<ServerConfig>,
}

fn setup() -> Setup {
    let ca = new_ca(&[HOST.to_owned()]).unwrap();
    let (upstream_ca, upstream) = upstream_pki(HOST);
    let tls = Tls::new(
        &ca.cert_pem,
        &ca.key_pem,
        &Roots::Pem(upstream_ca),
        &[HOST.to_owned()],
    )
    .unwrap();
    Setup {
        tls,
        broker: broker(),
        agent_trusts: ca.cert_pem,
        upstream,
    }
}

/// What one tunnel did.
struct Outcome {
    /// What the agent read, decrypted.
    agent: String,
    /// What the upstream read, decrypted; empty when nothing reached it.
    upstream: String,
    /// Each recorded decision with its method.
    rows: Vec<(Option<String>, Decision)>,
    /// How often the tunnel asked to connect upstream.
    connects: usize,
}

impl Outcome {
    fn rules(&self) -> Vec<String> {
        self.rows
            .iter()
            .flat_map(|(_, d)| d.rules.clone())
            .collect()
    }

    /// The value appears nowhere the agent or the audit log can see.
    fn kept_secret(&self) {
        assert!(
            !self.agent.contains(VALUE),
            "the agent read the value: {}",
            self.agent
        );
        for (_, d) in &self.rows {
            assert!(!format!("{d:?}").contains(VALUE), "{d:?}");
        }
    }
}

/// Options of one exchange.
struct Run<'a> {
    alpn: &'a [&'a [u8]],
    agent_trusts: Option<&'a str>,
    upstream: Option<Arc<ServerConfig>>,
    /// Bytes the agent sends after its request, to look for them upstream.
    after: &'a [u8],
}

const RUN: Run<'static> = Run {
    alpn: &[b"http/1.1"],
    agent_trusts: None,
    upstream: None,
    after: b"",
};

fn exchange(s: &Setup, request: &str, reply: &[u8]) -> Outcome {
    exchange_with(s, request, reply, &RUN)
}

fn exchange_with(s: &Setup, request: &str, reply: &[u8], run: &Run<'_>) -> Outcome {
    let (agent_sock, proxy_sock) = UnixStream::pair().unwrap();
    let (proxy_up, server_sock) = UnixStream::pair().unwrap();
    let server = serve_upstream(
        server_sock,
        run.upstream.clone().unwrap_or_else(|| s.upstream.clone()),
        reply,
    );
    let agent = agent(
        agent_sock,
        run.agent_trusts.unwrap_or(&s.agent_trusts),
        run.alpn,
        [request.as_bytes(), run.after].concat(),
    );
    let hello = read_hello(&proxy_sock);
    let rows = Mutex::new(Vec::new());
    let record = |method: Option<&str>, d: &Decision| {
        rows.lock()
            .unwrap()
            .push((method.map(str::to_owned), d.clone()));
        true
    };
    let mut connects = 0;
    let mut up = Some(proxy_up);
    let mut connect = || {
        connects += 1;
        up.take().ok_or_else(|| {
            (
                502,
                Decision::single(Verdict::Deny, "test", "connected twice"),
            )
        })
    };
    let allowed = Decision::single(Verdict::Allow, "test-hosts", "allowed by the test");
    let limits = Limits {
        handshake_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let tunnel = Tunnel {
        host: HOST,
        port: 443,
        broker: &s.broker,
        tls: &s.tls,
        limits: &limits,
        allowed: &allowed,
        record: &record,
        still_allowed: &|| true,
    };
    tunnel.serve(&proxy_sock, &hello, &mut connect);
    drop(proxy_sock);
    // An upstream never connected to sees its end close.
    drop(up);
    let agent = agent.join().unwrap();
    let upstream = server.recv_timeout(WAIT * 2).unwrap_or_default();
    Outcome {
        agent: String::from_utf8_lossy(&agent).into_owned(),
        upstream: String::from_utf8_lossy(&upstream).into_owned(),
        rows: rows.into_inner().unwrap(),
        connects,
    }
}

/// The proxy end reads the `ClientHello` first, as the server does.
fn read_hello(sock: &UnixStream) -> Vec<u8> {
    sock.set_read_timeout(Some(WAIT)).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match sni::server_name(&buf) {
            Ok(Hello::Incomplete) => {}
            Ok(_) | Err(_) => return buf,
        }
        let n = (&*sock).read(&mut chunk).unwrap();
        assert!(n > 0, "the agent closed before its ClientHello");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn agent(
    sock: UnixStream,
    trusts: &str,
    alpn: &[&[u8]],
    send: Vec<u8>,
) -> thread::JoinHandle<Vec<u8>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(trusts.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    thread::spawn(move || {
        sock.set_read_timeout(Some(WAIT)).unwrap();
        let conn =
            ClientConnection::new(Arc::new(config), ServerName::try_from(HOST).unwrap()).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        let _ = tls.write_all(&send).and_then(|()| tls.flush());
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = tls.read(&mut chunk) {
            out.extend_from_slice(&chunk[..n]);
        }
        out
    })
}

/// An upstream that reads one request (head and `Content-Length` body), says
/// what it read, and answers `reply`.
fn serve_upstream(
    sock: UnixStream,
    config: Arc<ServerConfig>,
    reply: &[u8],
) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let reply = reply.to_vec();
    thread::spawn(move || {
        sock.set_read_timeout(Some(WAIT)).unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), sock);
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        while !complete(&got) {
            match tls.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
        let reached = !got.is_empty();
        let _ = tx.send(got);
        if reached {
            let _ = tls.write_all(&reply);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    rx
}

/// Whether `got` holds a whole request with its `Content-Length` body.
fn complete(got: &[u8]) -> bool {
    let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    got.len() >= end + 4 + length
}

fn get(path: &str, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PLACEHOLDER}\r\n{extra}\r\n"
    )
}

#[test]
fn the_upstream_gets_the_value_and_the_agent_only_the_answer() {
    let s = setup();
    let out = exchange(
        &s,
        &get("/repos/o/r?per_page=1", "Accept-Encoding: gzip, br\r\n"),
        OK,
    );
    assert!(
        out.upstream
            .starts_with("GET /repos/o/r?per_page=1 HTTP/1.1\r\n"),
        "{}",
        out.upstream
    );
    assert!(
        out.upstream
            .contains(&format!("Authorization: Bearer {VALUE}\r\n")),
        "{}",
        out.upstream
    );
    assert!(!out.upstream.contains(PLACEHOLDER), "{}", out.upstream);
    assert!(
        out.upstream.contains("Accept-Encoding: identity\r\n"),
        "{}",
        out.upstream
    );
    assert!(!out.upstream.contains("gzip"), "{}", out.upstream);
    assert!(
        out.upstream.contains("Connection: close\r\n"),
        "{}",
        out.upstream
    );
    assert_eq!(
        out.agent,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    );
    out.kept_secret();
    assert_eq!(out.connects, 1);
    assert_eq!(out.rows.len(), 1, "{:?}", out.rows);
    let (method, row) = &out.rows[0];
    assert_eq!(method.as_deref(), Some("GET"));
    assert_eq!(row.verdict, Verdict::Allow);
    assert!(
        row.reasons
            .iter()
            .any(|r| r == "secret `gh` goes in: the request matches `GET /repos/**`"),
        "{row:?}"
    );
}

#[test]
fn a_post_with_a_body_and_expect_continue_is_relayed() {
    let s = setup();
    let body = r#"{"title":"hi"}"#;
    let request = format!(
        "POST /repos/o/r/issues HTTP/1.1\r\nHost: {HOST}:443\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\
         Expect: 100-continue\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let reply = b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nnew\r\n2\r\n!!\r\n0\r\n\r\n";
    let out = exchange(&s, &request, reply);
    assert!(out.upstream.ends_with(body), "{}", out.upstream);
    assert!(
        !out.upstream.to_ascii_lowercase().contains("expect:"),
        "{}",
        out.upstream
    );
    // The body came with the head, so no `100` was needed.
    assert!(
        out.agent.starts_with("HTTP/1.1 201 Created\r\n"),
        "{}",
        out.agent
    );
    // Sent again in the proxy's own chunks, ending in a last chunk.
    assert!(
        out.agent.ends_with(
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nnew!!\r\n0\r\n\r\n"
        ),
        "{}",
        out.agent
    );
    out.kept_secret();
}

#[test]
fn a_head_request_and_a_bodiless_answer_end_at_the_head() {
    let s = setup();
    let request = format!("HEAD /repos/o HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
    let out = exchange(
        &s,
        &request,
        b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n",
    );
    assert_eq!(
        out.agent,
        "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nConnection: close\r\n\r\n"
    );
    assert!(
        out.upstream
            .contains(&format!("Authorization: {VALUE}\r\n")),
        "added when absent: {}",
        out.upstream
    );
}

#[test]
fn a_redirect_is_passed_on_never_followed() {
    let s = setup();
    let reply =
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.test/collect\r\nContent-Length: 0\r\n\r\n";
    let out = exchange(&s, &get("/repos/o/r", ""), reply);
    assert!(
        out.agent
            .starts_with("HTTP/1.1 302 Found\r\nLocation: https://evil.test/collect\r\n"),
        "{}",
        out.agent
    );
    assert_eq!(
        out.connects, 1,
        "the proxy connects to the tunnel's host only"
    );
    out.kept_secret();
}
