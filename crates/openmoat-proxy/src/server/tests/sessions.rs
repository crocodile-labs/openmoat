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
    let policy =
        Policy::parse("version: 1\nallow:\n  - { id: hosts, net: [allowed.test] }\n").unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let address_policy = decide::address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address_policy, &ctx()).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let rows = Rows::default();
    let sessions = two_sessions(lookup);
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
        sessions: Some(&sessions),
        local: None,
    };
    let served = Served {
        addresses: &addresses,
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
