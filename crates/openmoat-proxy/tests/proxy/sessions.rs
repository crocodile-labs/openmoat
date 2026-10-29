//! Session mode (ADR-027) end to end: credentials, taint at egress and the
//! per-session share of the connections.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::sync::OnceLock;

use openmoat_core::{Taint, TaintSecret};
use openmoat_proxy::{Credential, TaintLookup};

use super::*;

/// A 64-character hex token made at run time, so no credential in these
/// tests is a fixed value: each `RandomState` is freshly keyed.
pub(super) fn fresh_token() -> String {
    let mut token = String::new();
    for _ in 0..4 {
        let random = RandomState::new().build_hasher().finish();
        write!(token, "{random:016x}").unwrap();
    }
    token
}

/// Session `run-a`'s token, the same for the whole test run.
fn token_a() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(fresh_token)
}

/// Session `run-b`'s token, the same for the whole test run.
fn token_b() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(fresh_token)
}

pub(super) struct Fixed(pub(super) HashMap<&'static str, Taint>);

impl TaintLookup for Fixed {
    fn taint(&self, session: &str) -> Result<Taint, String> {
        self.0
            .get(session)
            .cloned()
            .ok_or_else(|| "unknown".to_owned())
    }
}

pub(super) fn basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{password}");
    let mut out = String::from("Basic ");
    for chunk in raw.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// A proxy serving `run-a` (tainted by a secret read when `a_read_secret`)
/// and the clean `run-b`.
fn sessions_harness(a_read_secret: bool, limits: Limits) -> Harness {
    let a = if a_read_secret {
        Taint {
            secrets: vec![TaintSecret {
                source: "read /home/u/.config/token".to_owned(),
                host: None,
            }],
            untrusted: None,
        }
    } else {
        Taint::default()
    };
    let lookup: &'static Fixed = Box::leak(Box::new(Fixed(HashMap::from([
        ("run-a", a),
        ("run-b", Taint::default()),
    ]))));
    let sessions: &'static Sessions<'static> = Box::leak(Box::new(Sessions::new(
        vec![
            Credential::new("run-a", token_a().as_bytes()).unwrap(),
            Credential::new("run-b", token_b().as_bytes()).unwrap(),
        ],
        lookup,
    )));
    launch_with(None, limits, Broker::default(), upstream(), Some(sessions))
}

#[test]
fn a_tunnel_needs_its_sessions_credential() {
    let h = sessions_harness(false, Limits::default());
    let host = format!("allowed.test:{}", h.port());
    let reply = h.exchange(&format!("CONNECT {host} HTTP/1.1\r\n\r\n"));
    assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
    let wrong = basic("run-a", token_b());
    let reply = h.exchange(&format!(
        "CONNECT {host} HTTP/1.1\r\nProxy-Authorization: {wrong}\r\n\r\n"
    ));
    assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
    assert!(h.nothing_forwarded());

    let mut s = h.connect();
    let right = basic("run-a", token_a());
    write!(
        s,
        "CONNECT {host} HTTP/1.1\r\nProxy-Authorization: {right}\r\n\r\n"
    )
    .unwrap();
    let mut established = [0u8; 39];
    s.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    s.write_all(&client_hello("allowed.test")).unwrap();
    let forwarded = h.received.recv_timeout(WAIT).unwrap();
    assert_eq!(forwarded, client_hello("allowed.test"));
    let rows = h.rows();
    assert_eq!(rows.len(), 3);
    assert!(rows[..2].iter().all(|r| r.rules == ["proxy-session"]));
    assert_eq!(rows[2].rules, ["test-hosts"]);
}

#[test]
fn the_credential_never_reaches_the_upstream_or_the_audit_rows() {
    let h = sessions_harness(false, Limits::default());
    let credential = basic("run-b", token_b());
    let reply = h.exchange(&format!(
        "GET http://allowed.test:{}/p HTTP/1.1\r\nProxy-Authorization: {credential}\r\n\
         Content-Length: 0\r\n\r\n",
        h.port()
    ));
    assert!(reply.contains("ok"), "{reply}");
    let forwarded = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(!forwarded.contains(token_b()), "{forwarded}");
    assert!(!forwarded.contains(&credential[6..]), "{forwarded}");
    assert!(
        !forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    let rows = format!("{:?}", h.rows());
    assert!(
        !rows.contains(token_b()) && !rows.contains(&credential[6..]),
        "{rows}"
    );
}

#[test]
fn a_secret_tainted_session_cannot_reach_another_host_while_others_can() {
    let h = sessions_harness(true, Limits::default());
    let request = |session: &str, token: &str| {
        format!(
            "GET http://allowed.test:{}/ HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
            h.port(),
            basic(session, token)
        )
    };
    let reply = h.exchange(&request("run-a", token_a()));
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("session-taint"), "{reply}");
    assert!(h.nothing_forwarded());
    let reply = h.exchange(&request("run-b", token_b()));
    assert!(reply.contains("ok"), "{reply}");
}

#[test]
fn connections_that_never_authenticate_hold_at_most_half_the_slots() {
    let limits = Limits {
        max_connections: 4,
        handshake_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let h = sessions_harness(false, limits);
    let _silent: Vec<TcpStream> = (0..2).map(|_| h.connect()).collect();
    thread::sleep(Duration::from_millis(200));
    let mut third = h.connect();
    let reply = read_all(&mut third);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    assert!(reply.contains("waiting to authenticate"), "{reply}");
}

/// One session holding its half of the slots gets 503 for the next
/// connection, and another session is still served (#555).
#[test]
fn a_session_over_its_share_gets_503_while_another_is_served() {
    let limits = Limits {
        max_connections: 4,
        handshake_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let h = sessions_harness(false, limits);
    let host = format!("allowed.test:{}", h.port());
    let connect = |session: &str, token: &str| {
        format!(
            "CONNECT {host} HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
            basic(session, token)
        )
    };
    // Two tunnels of run-a that send no ClientHello: each holds run-a's share
    // until the handshake timeout.
    let _held: Vec<TcpStream> = (0..2)
        .map(|_| {
            let mut s = h.connect();
            s.write_all(connect("run-a", token_a()).as_bytes()).unwrap();
            let mut established = [0u8; 39];
            s.read_exact(&mut established).unwrap();
            assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
            s
        })
        .collect();
    let reply = h.exchange(&connect("run-a", token_a()));
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    assert!(reply.contains("half of the proxy's"), "{reply}");
    let reply = h.exchange(&format!(
        "GET http://{host}/ HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
        basic("run-b", token_b())
    ));
    assert!(reply.ends_with("ok"), "{reply}");
    assert!(
        h.rows()
            .iter()
            .any(|r| r.rules == ["proxy-session"] && r.dest.is_some()),
        "the refusal is recorded with its destination"
    );
}

/// A session's taint that a test can change while a connection is open.
struct Growing(Mutex<Taint>);

impl TaintLookup for Growing {
    fn taint(&self, _: &str) -> Result<Taint, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// A tunnel opened while the session was clean is closed, and the refusal
/// recorded, once the session reads secret material: its host is then refused.
#[test]
fn a_tunnel_opened_before_a_secret_read_is_closed_after_it() {
    let lookup: &'static Growing = Box::leak(Box::new(Growing(Mutex::new(Taint::default()))));
    let sessions: &'static Sessions<'static> = Box::leak(Box::new(Sessions::new(
        vec![Credential::new("run-a", token_a().as_bytes()).unwrap()],
        lookup,
    )));
    let limits = Limits {
        taint_recheck: Duration::from_millis(100),
        ..Limits::default()
    };
    // An upstream that keeps the tunnel open: it reads and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent = listener.local_addr().unwrap();
    let (tx, received) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                let mut buf = vec![0; 65536];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let h = launch_with(
        None,
        limits,
        Broker::default(),
        (silent, received),
        Some(sessions),
    );
    let mut s = h.connect();
    let right = basic("run-a", token_a());
    write!(
        s,
        "CONNECT allowed.test:{} HTTP/1.1\r\nProxy-Authorization: {right}\r\n\r\n",
        h.port()
    )
    .unwrap();
    let mut established = [0u8; 39];
    s.read_exact(&mut established).unwrap();
    s.write_all(&client_hello("allowed.test")).unwrap();
    assert_eq!(
        h.received.recv_timeout(WAIT).unwrap(),
        client_hello("allowed.test")
    );
    // The session reads a secret; the open tunnel is closed within a few checks.
    *lookup.0.lock().unwrap() = Taint {
        secrets: vec![TaintSecret {
            source: "read /home/u/.config/token".to_owned(),
            host: None,
        }],
        untrusted: None,
    };
    let started = std::time::Instant::now();
    assert_eq!(read_all(&mut s), "", "closed without an answer");
    assert!(started.elapsed() < Duration::from_secs(3));
    let _ = s.write_all(b"after");
    assert!(
        h.nothing_forwarded(),
        "nothing after the taint reached the upstream"
    );
    let rows = h.rows();
    assert_eq!(rows.first().map(|r| r.verdict), Some(Verdict::Allow));
    let last = rows.last().unwrap();
    assert_eq!(
        (last.verdict, last.rules.as_slice()),
        (Verdict::Deny, &["session-taint".to_owned()][..])
    );
    assert!(
        last.reasons.iter().any(|r| r.contains("taint grew")),
        "{:?}",
        last.reasons
    );
}
