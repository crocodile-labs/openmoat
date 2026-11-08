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

/// With `plain_http`, the secret names the upstream's port: plain-HTTP
/// injection goes to port 80 unless the secret names another.
fn brokered_to(upstream: (SocketAddr, Receiver<Vec<u8>>), plain_http: bool) -> Harness {
    let port = if plain_http {
        format!("    port: {}\n", upstream.0.port())
    } else {
        String::new()
    };
    let policy = Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: svc\n    host: owner.test\n    header: X-Api-Key\n    \
         source: {{ env: FAKE_SVC_KEY }}\n    plain_http: {plain_http}\n{port}",
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
    let safe = format!("{}{first}", "a".repeat(20_000));
    let _ = s.write_all(safe.as_bytes());
    thread::sleep(Duration::from_millis(100));
    let _ = s.write_all(second.as_bytes());
    let reply = read_all(&mut s);
    assert_no_value(&h, &reply);
    let forwarded = String::from_utf8(h.received.recv_timeout(SINK_WAIT).unwrap()).unwrap();
    assert!(forwarded.starts_with("POST / HTTP/1.1"), "{forwarded}");
    assert!(!forwarded.contains(VALUE));
    // The chunk the value completes in is never forwarded. On a slow machine
    // the proxy reads the end of the first write with the second (#590), so
    // what went upstream is the safe part, or less of it, never more.
    let (_, body) = forwarded.split_once("\r\n\r\n").expect("a forwarded head");
    assert!(
        safe.starts_with(body),
        "only the safe part, {} bytes forwarded",
        body.len()
    );
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

/// An upstream that answers each request with the request itself as the
/// body, as a debugging endpoint or an error page quoting a header does.
fn echo_upstream() -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = vec![0; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            let _ = tx.send(buf.clone());
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                buf.len()
            );
            let _ = stream.write_all(head.as_bytes());
            // In two writes, so the value may be split between reads.
            let (a, b) = buf.split_at(buf.len() / 2);
            let _ = stream.write_all(a);
            thread::sleep(Duration::from_millis(20));
            let _ = stream.write_all(b);
        }
    });
    (addr, rx)
}

/// Attack: the owner host of a `plain_http` secret echoes the request. The
/// value the proxy put in comes back in the answer, which is stopped before
/// the value reaches the client, and a `proxy-secret` row is written, as for
/// a terminated tunnel's answer.
#[test]
fn a_plain_http_answer_that_echoes_the_value_is_stopped() {
    let h = brokered_to(echo_upstream(), true);
    let port = h.port();
    let reply = h.exchange(&format!(
        "GET http://owner.test:{port}/ HTTP/1.1\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n"
    ));
    let head = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(head.contains(VALUE), "the owner got the value: {head}");
    assert!(!reply.contains(VALUE), "{reply}");
    let rows = h.rows();
    assert!(
        rows.iter().any(|r| r.rules == ["proxy-secret"]
            && r.reasons
                .iter()
                .any(|why| why.contains("holds the value of secret `svc`"))),
        "{rows:?}"
    );
    for row in &rows {
        assert!(!format!("{row:?}").contains(VALUE), "{row:?}");
    }
}

/// An answer that does not hold the value reaches the client whole, the
/// bytes held back to search included.
#[test]
fn a_plain_http_answer_without_the_value_reaches_the_client_whole() {
    let h = brokered_to(upstream(), true);
    let port = h.port();
    let reply = h.exchange(&format!(
        "GET http://owner.test:{port}/ HTTP/1.1\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n"
    ));
    assert!(reply.as_bytes().ends_with(UPSTREAM_REPLY), "{reply}");
    assert!(h.rows().iter().all(|r| r.rules == ["test-hosts"]));
}
