//! Session mode (ADR-027) end to end: credentials, taint at egress and the
//! per-session share of the connections.

use std::collections::HashMap;

use openmoat_core::{Taint, TaintSecret};
use openmoat_proxy::{Credential, TaintLookup};

use super::*;

const TOKEN_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

struct Fixed(HashMap<&'static str, Taint>);

impl TaintLookup for Fixed {
    fn taint(&self, session: &str) -> Result<Taint, String> {
        self.0
            .get(session)
            .cloned()
            .ok_or_else(|| "unknown".to_owned())
    }
}

fn basic(user: &str, password: &str) -> String {
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
            Credential::new("run-a", TOKEN_A.as_bytes()).unwrap(),
            Credential::new("run-b", TOKEN_B.as_bytes()).unwrap(),
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
    let wrong = basic("run-a", TOKEN_B);
    let reply = h.exchange(&format!(
        "CONNECT {host} HTTP/1.1\r\nProxy-Authorization: {wrong}\r\n\r\n"
    ));
    assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
    assert!(h.nothing_forwarded());

    let mut s = h.connect();
    let right = basic("run-a", TOKEN_A);
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
    let credential = basic("run-b", TOKEN_B);
    let reply = h.exchange(&format!(
        "GET http://allowed.test:{}/p HTTP/1.1\r\nProxy-Authorization: {credential}\r\n\
         Content-Length: 0\r\n\r\n",
        h.port()
    ));
    assert!(reply.contains("ok"), "{reply}");
    let forwarded = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(!forwarded.contains(TOKEN_B), "{forwarded}");
    assert!(!forwarded.contains(&credential[6..]), "{forwarded}");
    assert!(
        !forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    let rows = format!("{:?}", h.rows());
    assert!(
        !rows.contains(TOKEN_B) && !rows.contains(&credential[6..]),
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
    let reply = h.exchange(&request("run-a", TOKEN_A));
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("session-taint"), "{reply}");
    assert!(h.nothing_forwarded());
    let reply = h.exchange(&request("run-b", TOKEN_B));
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
