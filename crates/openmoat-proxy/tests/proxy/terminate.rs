//! TLS termination through a listening proxy (ADR-043): `CONNECT`, the SNI
//! check, the agent's handshake with the proxy's leaf, the request checked,
//! the value put in, and a local HTTPS upstream with a CA of its own. The
//! request and answer checks in depth are the unit tests in
//! `src/exchange/tests`; these prove the wiring.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use openmoat_proxy::{Roots, Tls, new_ca};
use zeroize::Zeroizing;

use super::*;

/// Generated for the test; no real secret is used.
const VALUE: &str = "fake-tls-wired-8d41c07a2e9b";
const PLACEHOLDER: &str = "moat-secret:svc:placeholder";

/// A CA of the upstream's own (PEM) and a TLS server for owner.test it signed.
fn upstream_tls() -> (String, Arc<ServerConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["owner.test".to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
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

/// An HTTPS upstream on loopback that reports each request head it reads and
/// answers `ok`.
fn https_upstream(config: Arc<ServerConfig>) -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            stream.set_read_timeout(Some(WAIT)).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), stream);
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tx.send(got);
            let _ = tls.write_all(UPSTREAM_REPLY);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    (addr, rx)
}

struct Terminating {
    h: Harness,
    /// The proxy's CA, which the agent trusts.
    agent_trusts: String,
    /// The upstream's own CA, for a client that reaches it directly.
    upstream_ca: String,
    /// The `Proxy-Authorization` line of the run's session (ADR-044).
    auth: String,
}

/// A proxy that terminates owner.test when `terminate`, with a secret whose
/// rules allow `GET /repos/**` only, serving one clean session.
fn terminating(terminate: bool) -> Terminating {
    terminating_with(terminate, false)
}

/// [`terminating`]; with `without_credential`, it also serves requests that
/// carry no credential, as a host sandbox's may be.
fn terminating_with(terminate: bool, without_credential: bool) -> Terminating {
    let (upstream_ca, config) = upstream_tls();
    let (addr, received) = https_upstream(config);
    let tls_line = if terminate {
        "    tls: terminate\n    allow: ['GET /repos/**']\n"
    } else {
        ""
    };
    let secrets = Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: svc\n    host: owner.test\n    header: Authorization\n    \
         source: {{ env: FAKE_SVC }}\n{tls_line}"
    ))
    .unwrap()
    .secrets
    .into_iter()
    .map(|s| (s, Zeroizing::new(VALUE.to_owned())))
    .collect();
    let ca = new_ca(&["owner.test".to_owned()]).unwrap();
    let tls: &'static Tls = Box::leak(Box::new(
        Tls::new(
            &ca.cert_pem,
            &ca.key_pem,
            &Roots::Pem(upstream_ca.clone()),
            &["owner.test".to_owned()],
        )
        .unwrap(),
    ));
    let token = super::sessions::fresh_token();
    let lookup: &'static super::sessions::Fixed = Box::leak(Box::new(super::sessions::Fixed(
        HashMap::from([("run-t", openmoat_core::Taint::default())]),
    )));
    let mut sessions = Sessions::new(
        vec![openmoat_proxy::Credential::new("run-t", token.as_bytes()).unwrap()],
        lookup,
    );
    if without_credential {
        sessions = sessions.serving_without_credential();
    }
    let sessions: &'static Sessions<'static> = Box::leak(Box::new(sessions));
    let h = launch_tls(
        Broker::new(secrets).unwrap(),
        (addr, received),
        tls,
        sessions,
    );
    Terminating {
        h,
        agent_trusts: ca.cert_pem,
        upstream_ca,
        auth: format!(
            "Proxy-Authorization: {}\r\n",
            super::sessions::basic("run-t", &token)
        ),
    }
}

fn launch_tls(
    broker: Broker,
    (upstream, received): (SocketAddr, Receiver<Vec<u8>>),
    tls: &'static Tls,
    sessions: &'static Sessions<'static>,
) -> Harness {
    let rows: &'static MemoryRecorder = Box::leak(Box::default());
    let resolver = MapResolver(HashMap::from([
        ("owner.test", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        ("allowed.test", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
    ]));
    let policy: &'static Policy = Box::leak(Box::new(on_port(POLICY, upstream.port())));
    let ctx = EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    };
    let proxy = Proxy {
        policy: Box::leak(Box::new(CompiledPolicy::compile(policy, &ctx).unwrap())),
        resolver: Box::leak(Box::new(resolver)),
        recorder: rows,
        limits: Box::leak(Box::new(Limits::default())),
        loopback_ok: Box::leak(Box::new([upstream])),
        broker: Box::leak(Box::new(broker)),
        allow_ech: false,
        sessions: Some(sessions),
        local: None,
        tls: Some(tls),
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || proxy.serve(&listener));
    Harness {
        proxy: addr,
        upstream,
        received,
        rows,
    }
}

/// CONNECT owner.test through the proxy with `auth` (a header line, or
/// nothing), then speak TLS trusting `ca` (with `sni` as the server name) and
/// send `request`. What came back, decrypted.
fn https(h: &Harness, auth: &str, ca: &str, sni: &str, request: &str) -> String {
    let mut s = h.connect();
    write!(
        s,
        "CONNECT owner.test:{} HTTP/1.1\r\nHost: owner.test\r\n{auth}\r\n",
        h.port()
    )
    .unwrap();
    let mut established = [0u8; 39];
    s.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap())
        .unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(sni.to_owned()).unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(conn, s);
    let _ = tls.write_all(request.as_bytes());
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n @ 1..) = tls.read(&mut chunk) {
        out.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A request inside the tunnel. Its `Host` names the port the tunnel was
/// opened to, as a client's does: one without a port names 443.
fn request(line: &str, port: u16) -> String {
    format!(
        "{line} HTTP/1.1\r\nHost: owner.test:{port}\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
    )
}

#[test]
fn a_terminated_tunnel_gets_the_value_in_and_never_out() {
    let t = terminating(true);
    let reply = https(
        &t.h,
        &t.auth,
        &t.agent_trusts,
        "owner.test",
        &request("GET /repos/o/r", t.h.port()),
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert!(reply.ends_with("\r\n\r\nok"), "{reply}");
    assert!(!reply.contains(VALUE), "{reply}");
    let head = String::from_utf8(t.h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(
        head.contains(&format!("Authorization: Bearer {VALUE}\r\n")),
        "{head}"
    );
    let rows = t.h.rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        (rows[0].tool.as_deref(), rows[0].terminated),
        (Some("CONNECT"), false)
    );
    assert!(
        rows[0].reasons.iter().any(|r| r.contains("is terminated")),
        "{rows:?}"
    );
    assert_eq!(
        (rows[1].tool.as_deref(), rows[1].terminated),
        (Some("GET"), true)
    );
    assert_eq!(rows[1].verdict, Verdict::Allow);
    assert!(rows.iter().all(|r| !format!("{r:?}").contains(VALUE)));
}

#[test]
fn a_request_the_rules_refuse_never_reaches_the_upstream() {
    let t = terminating(true);
    for line in ["DELETE /repos/o/r", "GET /repos/../user/keys", "GET /user"] {
        let reply = https(
            &t.h,
            &t.auth,
            &t.agent_trusts,
            "owner.test",
            &request(line, t.h.port()),
        );
        assert!(reply.starts_with("HTTP/1.1 403 "), "{line}: {reply}");
        assert!(reply.contains("proxy-secret-route"), "{reply}");
    }
    assert!(t.h.nothing_forwarded());
    let rows = t.h.rows();
    assert_eq!(
        rows.iter()
            .filter(|r| r.rules == ["proxy-secret-route"])
            .count(),
        3,
        "{rows:?}"
    );
}

#[test]
fn a_server_name_other_than_the_connect_host_is_refused_before_tls() {
    let t = terminating(true);
    let reply = https(
        &t.h,
        &t.auth,
        &t.agent_trusts,
        "evil.test",
        &request("GET /repos/o", t.h.port()),
    );
    assert!(reply.is_empty(), "{reply}");
    assert!(t.h.nothing_forwarded());
    let rows = t.h.rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].rules, ["proxy-sni"]);
}

#[test]
fn without_tls_terminate_the_tunnel_is_relayed_and_keeps_the_placeholder() {
    let t = terminating(false);
    // The agent talks to the upstream itself, end to end.
    let reply = https(
        &t.h,
        &t.auth,
        &t.upstream_ca,
        "owner.test",
        &request("DELETE /anything", t.h.port()),
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    let head = String::from_utf8(t.h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(
        head.contains(PLACEHOLDER) && !head.contains(VALUE),
        "{head}"
    );
    let rows = t.h.rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(!rows[0].terminated);
}

/// A request served without a credential (ADR-044) is no session's, so it is
/// never terminated: its tunnel is relayed and keeps the placeholder.
#[test]
fn a_request_without_a_session_is_never_terminated() {
    let t = terminating_with(true, true);
    let reply = https(
        &t.h,
        "",
        &t.upstream_ca,
        "owner.test",
        &request("DELETE /x", t.h.port()),
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    let head = String::from_utf8(t.h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(
        head.contains(PLACEHOLDER) && !head.contains(VALUE),
        "{head}"
    );
    let rows = t.h.rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(!rows[0].terminated);
    // Without a credential and without that opt-in, the CONNECT gets 407.
    let t = terminating(true);
    let mut s = t.h.connect();
    write!(s, "CONNECT owner.test:{} HTTP/1.1\r\n\r\n", t.h.port()).unwrap();
    assert!(read_all(&mut s).starts_with("HTTP/1.1 407"));
}
