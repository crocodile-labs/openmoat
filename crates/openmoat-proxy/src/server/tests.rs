use std::io::Read as _;
use std::net::{Ipv4Addr, Shutdown};
use std::sync::Mutex;
use std::time::Duration;

use openmoat_core::{EvalContext, Policy};

use super::*;
use crate::audit::RecordError;

mod sessions;

/// Every name resolves to loopback, where the test's upstream listens.
struct Local;

impl Resolve for Local {
    fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
    }
}

/// The rules of each recorded decision.
#[derive(Default)]
struct Rules(Mutex<Vec<Vec<String>>>);

impl Recorder for Rules {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        self.0.lock().unwrap().push(c.decision.rules.clone());
        Ok(())
    }
}

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    }
}

/// A policy that allows `allowed.test`, also on `port`, where the test's
/// upstream listens (a host rule alone allows 443 and 80 only).
fn allowed_on(port: u16) -> Policy {
    Policy::parse(&format!(
        "version: 1\nallow:\n  - {{ id: hosts, net: [allowed.test, 'allowed.test:{port}'] }}\n"
    ))
    .unwrap()
}

/// The proxy end of a loopback connection, and the client end.
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (proxy_end, _) = listener.accept().unwrap();
    (proxy_end, client)
}

#[test]
fn a_tunnel_whose_client_cannot_be_answered_is_recorded_and_gets_no_bytes() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let policy = allowed_on(upstream.local_addr().unwrap().port());
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let address_policy = decide::address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address_policy, &ctx()).unwrap();
    let port_policy = decide::port_policy(&policy);
    let ports = CompiledPolicy::compile(&port_policy, &ctx()).unwrap();
    let rules = Rules::default();
    let proxy = Proxy {
        policy: &compiled,
        resolver: &Local,
        recorder: &rules,
        limits: &Limits::default(),
        broker: &Broker::default(),
        loopback_ok: &[upstream.local_addr().unwrap()],
        allow_ech: false,
        sessions: None,
        local: None,
        tls: None,
    };
    let (proxy_end, mut client) = pair();
    let port = upstream.local_addr().unwrap().port();
    write!(client, "CONNECT allowed.test:{port} HTTP/1.1\r\n\r\n").unwrap();
    // The answer to the CONNECT cannot be written.
    proxy_end.shutdown(Shutdown::Write).unwrap();
    let served = Served {
        addresses: &addresses,
        ports: &ports,
        shares: Shares::new(8),
    };
    proxy.handle(&proxy_end, &served, None);
    assert_eq!(*rules.0.lock().unwrap(), [[RULE_SNI]]);
    let (mut opened, _) = upstream.accept().unwrap();
    let mut forwarded = Vec::new();
    opened.read_to_end(&mut forwarded).unwrap();
    assert!(forwarded.is_empty());
}

/// Answers `served` to a connection that starts with its prefix.
struct Echo;

impl LocalService for Echo {
    fn prefix(&self) -> &[u8] {
        b"MOAT-TEST/1\n"
    }

    fn serve(&self, mut client: &TcpStream) {
        // Read what was sent first, as the guard relay reads its whole request.
        // A socket closed with unread bytes is reset, and on Windows the reset
        // throws away what the other end had not read yet: "served".
        let _ = client.read_to_end(&mut Vec::new());
        let _ = client.write_all(b"served");
    }
}

/// What one connection that sends `request` gets with [`Echo`] on the port,
/// and the rules the proxy recorded.
fn with_echo(request: &[u8]) -> (String, Vec<Vec<String>>) {
    let policy = Policy::parse("version: 1\n").unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let address_policy = decide::address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address_policy, &ctx()).unwrap();
    let port_policy = decide::port_policy(&policy);
    let ports = CompiledPolicy::compile(&port_policy, &ctx()).unwrap();
    let rules = Rules::default();
    let proxy = Proxy {
        policy: &compiled,
        resolver: &Local,
        recorder: &rules,
        limits: &Limits::default(),
        broker: &Broker::default(),
        loopback_ok: &[],
        allow_ech: false,
        sessions: None,
        local: Some(&Echo),
        tls: None,
    };
    let (proxy_end, mut client) = pair();
    client.write_all(request).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let served = Served {
        addresses: &addresses,
        ports: &ports,
        shares: Shares::new(8),
    };
    proxy.handle(&proxy_end, &served, None);
    drop(proxy_end);
    let mut reply = String::new();
    let _ = client.read_to_string(&mut reply);
    (reply, rules.0.into_inner().unwrap())
}

#[test]
fn a_local_service_gets_its_connections_and_http_still_goes_to_the_proxy() {
    let (reply, rules) = with_echo(b"MOAT-TEST/1\nanything");
    assert_eq!(reply, "served");
    assert!(
        rules.is_empty(),
        "the service records for itself: {rules:?}"
    );
    let (reply, rules) = with_echo(b"GET http://a.test/ HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert_eq!(rules.len(), 1);
    // Part of the prefix is not the service's.
    let (reply, _) = with_echo(b"MOAT-TES");
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[test]
fn limits_that_cannot_serve_a_connection_are_refused() {
    assert!(Limits::default().check().is_ok());
    let cases = [
        Limits {
            max_head_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_connections: 0,
            ..Limits::default()
        },
        Limits {
            idle_timeout: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            handshake_timeout: Duration::MAX,
            ..Limits::default()
        },
    ];
    for limits in cases {
        let err = limits.check().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{limits:?}");
    }
}

#[test]
fn a_refusal_echoes_no_control_byte() {
    let (proxy_end, mut client) = pair();
    respond(&proxy_end, 403, "a.test\r\nX-Injected: 1");
    drop(proxy_end);
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert!(
        reply.ends_with("\r\n\r\nmoat proxy: a.test??X-Injected: 1\n"),
        "{reply:?}"
    );
}
