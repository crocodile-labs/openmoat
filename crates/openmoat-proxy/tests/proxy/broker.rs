use openmoat_core::Policy;
use zeroize::Zeroizing;

use super::*;

/// Generated for the test; no real secret is used.
const VALUE: &str = "fake-brokered-7c1e9a40d2b35f68";
const PLACEHOLDER: &str = "moat-secret:svc:placeholder";

fn brokered() -> Harness {
    brokered_to(upstream(), false)
}

/// How long a test waits for the [`sink`]'s report: clearly longer than its
/// read timeout ([`WAIT`]), which starts before the test begins waiting (#553).
const SINK_WAIT: Duration = Duration::from_secs(15);

/// An upstream that reports everything it received once the connection ends.
fn sink() -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut all = Vec::new();
        let _ = stream.read_to_end(&mut all);
        let _ = tx.send(all);
    });
    (addr, rx)
}

fn brokered_to(upstream: (SocketAddr, Receiver<Vec<u8>>), plain_http: bool) -> Harness {
    let policy = Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: svc\n    host: owner.test\n    header: X-Api-Key\n    \
         source: {{ env: FAKE_SVC_KEY }}\n    plain_http: {plain_http}\n",
    ))
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(VALUE.to_owned())))
        .collect();
    launch(
        None,
        Limits::default(),
        Broker::new(secrets).unwrap(),
        upstream,
    )
}

fn assert_no_value(h: &Harness, reply: &str) {
    assert!(!reply.contains(VALUE), "{reply}");
    for row in h.rows() {
        assert!(!format!("{row:?}").contains(VALUE), "{row:?}");
    }
}

#[test]
fn a_secret_bound_elsewhere_is_refused_in_any_part_of_the_head() {
    let h = brokered();
    let port = h.port();
    let requests = [
        format!("GET http://allowed.test:{port}/?k={VALUE} HTTP/1.1\r\n\r\n"),
        format!("GET http://allowed.test:{port}/ HTTP/1.1\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n"),
        format!("GET http://unknown.test/{PLACEHOLDER} HTTP/1.1\r\n\r\n"),
        format!("CONNECT allowed.test:{port} HTTP/1.1\r\nX-K: {VALUE}\r\n\r\n"),
        format!(
            "POST http://allowed.test:{port}/ HTTP/1.1\r\nContent-Length: {}\r\n\r\nk={VALUE}",
            VALUE.len() + 2
        ),
    ];
    for request in &requests {
        let reply = h.exchange(request);
        assert!(reply.starts_with("HTTP/1.1 403"), "{request}: {reply}");
        assert!(
            reply.contains("secret `svc`, which only owner.test"),
            "{reply}"
        );
        assert_no_value(&h, &reply);
    }
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(rows.len(), requests.len());
    assert!(rows.iter().all(|r| r.rules == ["proxy-secret"]), "{rows:?}");
}

#[test]
fn a_secret_later_in_a_streamed_body_closes_the_connection() {
    let h = brokered_to(sink(), false);
    let port = h.port();
    let mut s = h.connect();
    write!(
        s,
        "POST http://allowed.test:{port}/ HTTP/1.1\r\nContent-Length: 70000\r\n\r\n"
    )
    .unwrap();
    // The value straddles two writes, after padding the proxy relays.
    let (first, second) = VALUE.split_at(9);
    let _ = s.write_all(format!("{}{first}", "a".repeat(20_000)).as_bytes());
    thread::sleep(Duration::from_millis(100));
    let _ = s.write_all(second.as_bytes());
    let reply = read_all(&mut s);
    assert_no_value(&h, &reply);
    let forwarded = String::from_utf8(h.received.recv_timeout(SINK_WAIT).unwrap()).unwrap();
    assert!(forwarded.starts_with("POST / HTTP/1.1"), "{forwarded}");
    assert!(forwarded.ends_with(first), "relayed up to the split");
    assert!(!forwarded.contains(VALUE));
    let rows = h.rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].rules, ["test-hosts"]);
    assert_eq!(rows[1].rules, ["proxy-secret"]);
    assert!(
        rows[1].reasons[0].contains("value of secret `svc`"),
        "{rows:?}"
    );
}

#[test]
fn without_plain_http_the_owner_host_keeps_the_placeholder() {
    let h = brokered();
    let port = h.port();
    let reply = h.exchange(&format!(
        "GET http://owner.test:{port}/ HTTP/1.1\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n"
    ));
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let head = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(!head.contains(VALUE), "{head}");
    assert!(
        head.contains(&format!("X-Api-Key: {PLACEHOLDER}\r\n")),
        "{head}"
    );
    assert_no_value(&h, &reply);
    let rows = h.rows();
    assert_eq!(rows[0].rules, ["test-hosts"]);
    assert!(
        rows[0]
            .reasons
            .iter()
            .any(|r| r == "secret `svc` not injected: plain HTTP needs `plain_http: true`"),
        "{rows:?}"
    );
}

#[test]
fn with_plain_http_the_owner_host_gets_the_value_and_the_client_never_sees_it() {
    let h = brokered_to(upstream(), true);
    let port = h.port();
    let cases = [
        (
            format!("x-api-key: k={PLACEHOLDER}\r\n"),
            format!("x-api-key: k={VALUE}\r\n"),
        ),
        (String::new(), format!("X-Api-Key: {VALUE}\r\n")),
        (
            "X-Api-Key: chosen\r\n".to_owned(),
            format!("X-Api-Key: {VALUE}\r\n"),
        ),
    ];
    for (sent, expected) in cases {
        let reply = h.exchange(&format!(
            "GET http://owner.test:{port}/ HTTP/1.1\r\n{sent}\r\n"
        ));
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert_no_value(&h, &reply);
        let head = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
        assert!(head.contains(&expected), "{head}");
        assert!(
            !head.contains(PLACEHOLDER) && !head.contains("chosen"),
            "{head}"
        );
    }
    assert!(h.rows().iter().all(|r| r.rules == ["test-hosts"]));
    let reply = h.exchange(&format!("GET http://allowed.test:{port}/ HTTP/1.1\r\n\r\n"));
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let head = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(!head.to_ascii_lowercase().contains("x-api-key"), "{head}");
}

#[test]
fn a_secret_split_between_the_head_read_and_the_body_is_caught() {
    let h = brokered_to(sink(), false);
    let port = h.port();
    let mut s = h.connect();
    // The head and the first part of the value arrive in one read.
    let (first, second) = VALUE.split_at(9);
    write!(
        s,
        "POST http://allowed.test:{port}/ HTTP/1.1\r\nContent-Length: 100\r\n\r\nk={first}"
    )
    .unwrap();
    thread::sleep(Duration::from_millis(100));
    let _ = s.write_all(second.as_bytes());
    let reply = read_all(&mut s);
    assert_no_value(&h, &reply);
    let forwarded = String::from_utf8(h.received.recv_timeout(SINK_WAIT).unwrap()).unwrap();
    assert!(forwarded.ends_with(&format!("k={first}")), "{forwarded}");
    let rows = h.rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[1].rules, ["proxy-secret"]);
}
