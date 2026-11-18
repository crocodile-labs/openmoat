//! Request rules (`requests:`, ADR-062) through a listening proxy: which
//! sessions' tunnels to a `requests:` host are terminated, what happens to
//! one that cannot be (`requests_untrusted`), and a tainted session's
//! read-only access. The rules' matching in depth is `src/requests/tests.rs`
//! and the core's.

use openmoat_core::rule_id::{REQUEST_RULE, SESSION_TAINT};
use openmoat_core::{RequestEntry, RequestsUntrusted, Taint, TaintSecret};
use openmoat_proxy::{Requests, Roots, Tls, Verify, new_ca};

use super::terminate::{https, https_upstream, launch_tls, request, upstream_tls};
use super::*;

const ISSUED: &str = "issued-s";

/// An issued credential (the standalone proxy's sessions, ADR-044) whose
/// session did or did not receive the CA's trust files.
struct Issued {
    token: String,
    trusted: bool,
}

impl Verify for Issued {
    fn verify(&self, user: &[u8], password: &[u8]) -> Option<String> {
        (user == ISSUED.as_bytes() && password == self.token.as_bytes()).then(|| ISSUED.to_owned())
    }

    fn trusted(&self, user: &[u8]) -> bool {
        user == ISSUED.as_bytes() && self.trusted
    }
}

struct Ruled {
    h: Harness,
    agent_trusts: String,
    auth: String,
}

/// A proxy whose request rules refuse `POST /gists` on owner.test, serving
/// one issued session (trusted or not), tainted by a secret read when `read_secret`.
fn ruled(trusted: bool, untrusted: RequestsUntrusted, read_secret: bool) -> Ruled {
    let (upstream_ca, config) = upstream_tls();
    let (addr, received) = https_upstream(config);
    let ca = new_ca(&["owner.test".to_owned()]).unwrap();
    let tls: &'static Tls = Box::leak(Box::new(
        Tls::new(
            &ca.cert_pem,
            &ca.key_pem,
            &Roots::Pem(upstream_ca),
            &["owner.test".to_owned()],
        )
        .unwrap(),
    ));
    let entry = RequestEntry {
        id: "gists".to_owned(),
        host: "owner.test".to_owned(),
        allow: Vec::new(),
        deny: vec!["POST /gists".to_owned()],
        hook_only: false,
    };
    let requests: &'static Requests =
        Box::leak(Box::new(Requests::new(&[entry], untrusted).unwrap()));
    let taint = if read_secret {
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
    let lookup: &'static super::sessions::Fixed = Box::leak(Box::new(super::sessions::Fixed(
        HashMap::from([(ISSUED, taint)]),
    )));
    let token = super::sessions::fresh_token();
    let issued: &'static Issued = Box::leak(Box::new(Issued {
        token: token.clone(),
        trusted,
    }));
    let sessions: &'static Sessions<'static> =
        Box::leak(Box::new(Sessions::issued(issued, lookup)));
    let h = launch_tls(
        Broker::default(),
        (addr, received),
        (tls, requests),
        sessions,
    );
    Ruled {
        h,
        agent_trusts: ca.cert_pem,
        auth: format!(
            "Proxy-Authorization: {}\r\n",
            super::sessions::basic(ISSUED, &token)
        ),
    }
}

impl Ruled {
    fn send(&self, line: &str) -> String {
        https(
            &self.h,
            &self.auth,
            &self.agent_trusts,
            "owner.test",
            &request(line, self.h.port()),
        )
    }

    /// The answer to the CONNECT alone.
    fn connect(&self) -> String {
        let mut s = self.h.connect();
        write!(
            s,
            "CONNECT owner.test:{} HTTP/1.1\r\nHost: owner.test\r\n{}\r\n",
            self.h.port(),
            self.auth
        )
        .unwrap();
        let mut answer = [0u8; 12];
        let _ = s.read_exact(&mut answer);
        String::from_utf8_lossy(&answer).into_owned()
    }
}

#[test]
fn a_session_that_received_the_ca_is_terminated_and_its_denied_requests_stay_local() {
    let t = ruled(true, RequestsUntrusted::Refuse, false);
    let reply = t.send("POST /gists");
    assert!(reply.starts_with("HTTP/1.1 403 "), "{reply}");
    assert!(reply.contains(REQUEST_RULE), "{reply}");
    assert!(t.h.nothing_forwarded());
    let reply = t.send("GET /gists");
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert!(t.h.rows().iter().any(|r| r.terminated));
}

#[test]
fn a_session_without_the_ca_is_refused_by_default() {
    let t = ruled(false, RequestsUntrusted::Refuse, false);
    let answer = t.connect();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    let rows = t.h.rows();
    assert!(rows.iter().any(|r| r.rules == [REQUEST_RULE]), "{rows:?}");
    assert!(rows.iter().all(|r| !r.terminated), "{rows:?}");
    assert!(t.h.nothing_forwarded());
}

#[test]
fn a_session_without_the_ca_is_relayed_unread_when_the_policy_says_relay() {
    let t = ruled(false, RequestsUntrusted::Relay, false);
    let answer = t.connect();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let rows = t.h.rows();
    let noted = rows.iter().any(|r| {
        r.verdict == Verdict::Allow && r.reasons.iter().any(|w| w.contains("relayed unread"))
    });
    assert!(noted, "{rows:?}");
    assert!(rows.iter().all(|r| !r.terminated), "{rows:?}");
}

#[test]
fn a_tainted_session_reads_from_a_requests_host_and_writes_nothing() {
    let t = ruled(true, RequestsUntrusted::Refuse, true);
    let reply = t.send("GET /repos/o/r");
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    let head = String::from_utf8(t.h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(head.starts_with("GET /repos/o/r "), "{head}");
    let reply = t.send("POST /repos/o/r/issues");
    assert!(reply.starts_with("HTTP/1.1 403 "), "{reply}");
    assert!(reply.contains(SESSION_TAINT), "{reply}");
    assert!(t.h.nothing_forwarded());
}

#[test]
fn a_tainted_session_without_the_ca_keeps_the_whole_host_refusal() {
    let t = ruled(false, RequestsUntrusted::Relay, true);
    let answer = t.connect();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    let rows = t.h.rows();
    assert!(
        rows.iter()
            .any(|r| r.rules.iter().any(|x| x == SESSION_TAINT)),
        "{rows:?}"
    );
}
