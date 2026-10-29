//! Session mode (ADR-027) through `Proxy::handle` on a loopback pair.

use std::collections::HashMap;

use openmoat_core::{Taint, TaintSecret};

use super::*;
use crate::session::tests::{Fixed, fresh_token, header, token_a, token_b, two_sessions};

/// One recorded row: its session, rules, and everything it holds as text.
type Row = (Option<String>, Vec<String>, String);

#[derive(Default)]
struct Rows(Mutex<Vec<Row>>);

impl Recorder for Rows {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        self.0.lock().unwrap().push((
            c.session.map(str::to_owned),
            c.decision.rules.clone(),
            format!("{c:?}"),
        ));
        Ok(())
    }
}

fn secret_read() -> Taint {
    Taint {
        secrets: vec![TaintSecret {
            source: "read /home/u/.config/token".to_owned(),
            host: None,
        }],
        untrusted: None,
    }
}

/// What one plain-HTTP request with `credential` gets: the client's reply,
/// the bytes the upstream received, and the rows. `held` connections of
/// `run-a` are open already.
fn exchange(lookup: &Fixed, credential: Option<&str>, held: usize) -> (String, Vec<u8>, Vec<Row>) {
    exchange_with(&two_sessions(lookup), credential, held)
}

/// [`exchange`] with `sessions`; `held` connections of `run-a` are open already.
fn exchange_with(
    sessions: &Sessions<'_>,
    credential: Option<&str>,
    held: usize,
) -> (String, Vec<u8>, Vec<Row>) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let policy = super::allowed_on(upstream.local_addr().unwrap().port());
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let address_policy = decide::address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address_policy, &ctx()).unwrap();
    let port_policy = decide::port_policy(&policy);
    let ports = CompiledPolicy::compile(&port_policy, &ctx()).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let rows = Rows::default();
    let limits = Limits {
        idle_timeout: Duration::from_millis(300),
        max_connections: 4,
        ..Limits::default()
    };
    let proxy = Proxy {
        policy: &compiled,
        resolver: &Local,
        recorder: &rows,
        limits: &limits,
        broker: &Broker::default(),
        loopback_ok: &[upstream.local_addr().unwrap()],
        allow_ech: false,
        sessions: Some(sessions),
        local: None,
    };
    let served = Served {
        addresses: &addresses,
        ports: &ports,
        shares: Shares::new(limits.max_connections),
    };
    let _held: Vec<_> = (0..held)
        .map(|_| served.shares.take("run-a").unwrap())
        .collect();
    let (proxy_end, mut client) = pair();
    let port = upstream.local_addr().unwrap().port();
    let auth = credential.map_or(String::new(), |c| format!("Proxy-Authorization: {c}\r\n"));
    write!(
        client,
        "GET http://allowed.test:{port}/x HTTP/1.1\r\n{auth}Content-Length: 0\r\n\r\n"
    )
    .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    proxy.handle(&proxy_end, &served, None);
    drop(proxy_end);
    let mut reply = String::new();
    let _ = client.read_to_string(&mut reply);
    let mut forwarded = Vec::new();
    if let Ok((mut opened, _)) = upstream.accept() {
        opened.set_nonblocking(false).unwrap();
        opened
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let _ = opened.read_to_end(&mut forwarded);
    }
    let rows = rows.0.into_inner().unwrap();
    (reply, forwarded, rows)
}

#[test]
fn a_request_without_a_valid_credential_gets_407_and_reaches_nothing() {
    let lookup = Fixed(HashMap::from([("run-a", Taint::default())]));
    for credential in [
        None,
        // A well-formed token that no session holds.
        Some(header("run-a", &fresh_token())),
        // Session A's token presented as session B.
        Some(header("run-b", token_a())),
        Some("Basic !!!".to_owned()),
    ] {
        let (reply, forwarded, rows) = exchange(&lookup, credential.as_deref(), 0);
        assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
        assert!(
            reply.contains("Proxy-Authenticate: Basic realm=\"moat\""),
            "{reply}"
        );
        assert!(forwarded.is_empty(), "{credential:?} reached the upstream");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].0.as_deref(), rows[0].1.as_slice()),
            (None, &[RULE_SESSION.to_owned()][..])
        );
    }
}

#[test]
fn a_valid_credential_is_recorded_as_its_session_and_never_forwarded() {
    let lookup = Fixed(HashMap::from([("run-a", Taint::default())]));
    let credential = header("run-a", token_a());
    let (_, forwarded, rows) = exchange(&lookup, Some(&credential), 0);
    let forwarded = String::from_utf8_lossy(&forwarded);
    assert!(forwarded.starts_with("GET /x HTTP/1.1\r\n"), "{forwarded}");
    assert!(!forwarded.contains(token_a()) && !forwarded.contains(&credential[6..]));
    assert!(
        !forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0.as_deref(), Some("run-a"));
    assert_eq!(rows[0].1, ["hosts"]);
    // Nothing of the credential is in what the audit log is given.
    assert!(!rows[0].2.contains(token_a()) && !rows[0].2.contains(&credential[6..]));
}

#[test]
fn a_session_that_read_a_secret_cannot_reach_another_host() {
    let lookup = Fixed(HashMap::from([
        ("run-a", secret_read()),
        ("run-b", Taint::default()),
    ]));
    let (reply, forwarded, rows) = exchange(&lookup, Some(&header("run-a", token_a())), 0);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("session-taint"), "{reply}");
    assert!(forwarded.is_empty());
    assert_eq!(rows[0].0.as_deref(), Some("run-a"));
    assert_eq!(rows[0].1, ["session-taint"]);
    // Session B's own clean history still lets it through.
    let (_, forwarded, rows) = exchange(&lookup, Some(&header("run-b", token_b())), 0);
    assert!(!forwarded.is_empty());
    assert_eq!(rows[0].0.as_deref(), Some("run-b"));
}

#[test]
fn a_session_whose_history_cannot_be_read_is_refused() {
    // The lookup knows no `run-a`, as when the audit log cannot be read.
    let lookup = Fixed(HashMap::new());
    let (reply, forwarded, rows) = exchange(&lookup, Some(&header("run-a", token_a())), 0);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(forwarded.is_empty());
    assert_eq!(rows[0].1, [RULE_SESSION]);
}

#[test]
fn a_session_holding_half_the_slots_gets_503() {
    let lookup = Fixed(HashMap::from([
        ("run-a", Taint::default()),
        ("run-b", Taint::default()),
    ]));
    // `max_connections` is 4: run-a already holds its 2.
    let (reply, forwarded, rows) = exchange(&lookup, Some(&header("run-a", token_a())), 2);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    assert!(forwarded.is_empty());
    assert_eq!(
        (rows[0].0.as_deref(), rows[0].1.as_slice()),
        (Some("run-a"), &[RULE_SESSION.to_owned()][..])
    );
    let (_, forwarded, _) = exchange(&lookup, Some(&header("run-a", token_a())), 1);
    assert!(!forwarded.is_empty(), "a session under its share is served");
}

/// The standalone proxy (ADR-044): the credentials a verifier accepts.
#[test]
fn an_issued_credential_is_served_as_its_session_and_others_get_407() {
    use crate::session::tests::Issued;
    let lookup = Fixed(HashMap::from([
        ("claude-a", Taint::default()),
        ("claude-b", secret_read()),
    ]));
    let a = Issued::new("claude-a");
    let sessions = Sessions::issued(&a, &lookup);
    let (_, forwarded, rows) = exchange_with(&sessions, Some(&header(&a.user, &a.password)), 0);
    assert!(!forwarded.is_empty());
    assert_eq!(rows[0].0.as_deref(), Some("claude-a"));
    assert!(!rows[0].2.contains(&a.password));
    // No credential, or a password the verifier does not accept: 407.
    for credential in [None, Some(header(&a.user, &fresh_token()))] {
        let (reply, forwarded, rows) = exchange_with(&sessions, credential.as_deref(), 0);
        assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
        assert!(forwarded.is_empty());
        assert_eq!(rows[0].1, [RULE_SESSION]);
    }
    // A tainted session's own credential carries its taint.
    let b = Issued::new("claude-b");
    let sessions = Sessions::issued(&b, &lookup);
    let (reply, forwarded, _) = exchange_with(&sessions, Some(&header(&b.user, &b.password)), 0);
    assert!(reply.contains("session-taint"), "{reply}");
    assert!(forwarded.is_empty());
}

/// `sandbox.proxy_serve_without_credential`: a request with no credential is
/// served with no session and no taint; a wrong one is still refused, so a
/// session cannot pass for another by sending a bad credential.
#[test]
fn serving_without_a_credential_serves_none_and_still_refuses_a_wrong_one() {
    use crate::session::tests::Issued;
    let lookup = Fixed(HashMap::from([("claude-a", secret_read())]));
    let a = Issued::new("claude-a");
    let sessions = Sessions::issued(&a, &lookup).serving_without_credential();
    let (reply, forwarded, rows) = exchange_with(&sessions, None, 0);
    assert!(!forwarded.is_empty(), "{reply}");
    assert_eq!(rows[0].0, None);
    assert_eq!(rows[0].1, ["hosts"]);
    // A well-formed password made at run time that the verifier does not accept.
    let wrong = fresh_token();
    let (reply, forwarded, _) = exchange_with(&sessions, Some(&header(&a.user, &wrong)), 0);
    assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
    assert!(forwarded.is_empty());
    // The tainted session's own credential is still refused at egress.
    let (reply, _, _) = exchange_with(&sessions, Some(&header(&a.user, &a.password)), 0);
    assert!(reply.contains("session-taint"), "{reply}");
}
