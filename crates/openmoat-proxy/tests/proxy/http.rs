use super::*;

#[test]
fn an_allowed_host_is_forwarded_over_plain_http() {
    let h = start(None, Limits::default());
    let port = h.port();
    let reply = h.exchange(&format!(
        "GET http://allowed.test:{port}/x?y=1 HTTP/1.1\r\nHost: allowed.test:{port}\r\n\
         Proxy-Authorization: Basic c2VjcmV0\r\nUser-Agent: t\r\n\r\n"
    ));
    assert!(
        reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("ok"),
        "{reply}"
    );
    let head = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert_eq!(
        head,
        format!(
            "GET /x?y=1 HTTP/1.1\r\nHost: allowed.test:{port}\r\nUser-Agent: t\r\n\
             Connection: close\r\n\r\n"
        )
    );
    let rows = h.rows();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.tool.as_deref(), Some("GET"));
    assert_eq!(
        (row.verdict, row.rules.as_slice()),
        (Verdict::Allow, &["test-hosts".to_owned()][..])
    );
    assert_eq!(row.dest, Some(("allowed.test".to_owned(), port)));
}

#[test]
fn an_unknown_host_is_refused_with_403_and_recorded() {
    let h = start(None, Limits::default());
    let reply = h.exchange("GET http://unknown.test/ HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden"), "{reply}");
    assert!(reply.contains("default.fetch"), "{reply}");
    assert!(h.nothing_forwarded());
    let reply = h.exchange("CONNECT unknown.test:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden"), "{reply}");
    let rows = h.rows();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.verdict == Verdict::Deny && r.rules == ["default.fetch"])
    );
    assert!(rows.iter().any(|r| r.tool.as_deref() == Some("CONNECT")
        && r.dest == Some(("unknown.test".to_owned(), 443))));
}

#[test]
fn metadata_is_refused_even_through_an_allowed_name() {
    let h = start(None, Limits::default());
    for host in ["rebind.test", "mixed.test", "169.254.169.254"] {
        let reply = h.exchange(&format!(
            "GET http://{host}:{}/latest/meta-data/ HTTP/1.1\r\n\r\n",
            h.port()
        ));
        assert!(reply.starts_with("HTTP/1.1 403"), "{host}: {reply}");
        assert!(reply.contains("link-local"), "{host}: {reply}");
    }
    assert!(h.nothing_forwarded());
    assert!(h.rows().iter().all(|r| r.rules == ["proxy-address"]));
}

#[test]
fn loopback_is_refused_unless_it_is_the_listed_server() {
    let h = start(None, Limits::default());
    // loop.test resolves to 127.0.0.1 too, but on a port nobody listed (the
    // policy allows `loop.test:1`, so the loopback check is what refuses it)
    let reply = h.exchange("GET http://loop.test:1/ HTTP/1.1\r\n\r\n");
    assert!(
        reply.starts_with("HTTP/1.1 403") && reply.contains("loopback"),
        "{reply}"
    );
}

#[test]
fn a_pipelined_second_request_is_never_forwarded() {
    // The proxy decided the first request only. A second one after its body,
    // here for a host the policy refuses, must not reach the first host's
    // server, whatever that server would make of it.
    let h = start(None, Limits::default());
    let port = h.port();
    let second = "GET http://unknown.test/ HTTP/1.1\r\nHost: unknown.test\r\n\r\n";
    let cases = [
        ("Content-Length: 5\r\n", "hello"),
        ("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"),
    ];
    for (framing, body) in cases {
        let reply = h.exchange(&format!(
            "POST http://allowed.test:{port}/a HTTP/1.1\r\nHost: allowed.test:{port}\r\n\
             {framing}\r\n{body}{second}"
        ));
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        let forwarded = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
        assert_eq!(
            forwarded,
            format!(
                "POST /a HTTP/1.1\r\nHost: allowed.test:{port}\r\n{framing}\
                 Connection: close\r\n\r\n{body}"
            )
        );
    }
}

#[test]
fn a_request_without_a_body_forwards_nothing_after_its_head() {
    let h = start(None, Limits::default());
    let port = h.port();
    let reply = h.exchange(&format!(
        "GET http://allowed.test:{port}/ HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n\
         GET http://allowed.test:{port}/second HTTP/1.1\r\n\r\n"
    ));
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    let forwarded = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(!forwarded.contains("/second"), "{forwarded}");
}

#[test]
fn a_chunked_body_the_proxy_cannot_follow_is_refused() {
    let h = start(None, Limits::default());
    let port = h.port();
    let reply = h.exchange(&format!(
        "POST http://allowed.test:{port}/a HTTP/1.1\r\nHost: allowed.test:{port}\r\n\
         Transfer-Encoding: chunked\r\n\r\n5 5\r\nhello\r\n0\r\n\r\n"
    ));
    assert!(reply.starts_with("HTTP/1.1 400 Bad Request"), "{reply}");
    assert!(reply.contains("malformed chunked"), "{reply}");
    assert!(h.nothing_forwarded());
    assert!(h.rows().iter().any(|r| r.verdict == Verdict::Deny));
}

#[test]
fn a_chunked_body_that_goes_wrong_after_the_head_is_cut_and_recorded() {
    // The head and a good chunk are allowed and forwarded; the malformed
    // chunk size comes in a later read, which the relay checks.
    let h = start(None, Limits::default());
    let port = h.port();
    let mut s = h.connect();
    s.write_all(
        format!(
            "POST http://allowed.test:{port}/a HTTP/1.1\r\nHost: allowed.test:{port}\r\n\
             Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let forwarded = String::from_utf8(h.received.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(forwarded.ends_with("5\r\nhello\r\n"), "{forwarded}");
    s.write_all(b"5 5\r\nhello\r\n0\r\n\r\n").unwrap();
    let _ = read_all(&mut s);
    let deadline = std::time::Instant::now() + WAIT;
    while h.rows().len() < 2 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let rows = h.rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].verdict, Verdict::Allow);
    assert_eq!(
        (rows[1].verdict, rows[1].rules.as_slice()),
        (Verdict::Deny, &["proxy-request".to_owned()][..])
    );
    assert!(rows[1].reasons[0].contains("malformed chunked"), "{rows:?}");
}

#[test]
fn a_refused_upload_still_reads_the_403() {
    // The proxy refuses before reading the body. Closing with that body
    // unread resets the connection, and the client loses the 403 it was sent.
    let h = start(None, Limits::default());
    let mut s = h.connect();
    let body = vec![b'x'; 256 * 1024];
    let head = format!(
        "POST http://unknown.test/ HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    thread::sleep(Duration::from_millis(100));
    let _ = s.write_all(&body);
    let reply = read_all(&mut s);
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden"), "{reply:?}");
}
