use super::*;

#[test]
fn a_tunnel_whose_sni_matches_is_relayed() {
    let h = start(None, Limits::default());
    let (_, reply) = tunnel(&h, "allowed.test", "allowed.test");
    assert_eq!(reply.as_bytes(), UPSTREAM_REPLY);
    assert_eq!(
        h.received.recv_timeout(WAIT).unwrap(),
        client_hello("allowed.test")
    );
    let rows = h.rows();
    assert_eq!((rows.len(), rows[0].verdict), (1, Verdict::Allow));
}

#[test]
fn a_tunnel_whose_sni_names_another_host_is_closed_unforwarded() {
    let h = start(None, Limits::default());
    let (_, reply) = tunnel(&h, "allowed.test", "evil.test");
    assert_eq!(reply, "");
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(
        (rows[0].verdict, rows[0].rules.as_slice()),
        (Verdict::Deny, &["proxy-sni".to_owned()][..])
    );
    assert!(
        rows[0].reasons[0].contains("evil.test"),
        "{:?}",
        rows[0].reasons
    );
}

/// With ECH the server acts on the encrypted inner name, which may be another
/// site behind the allowed host's provider: such a tunnel is refused.
#[test]
fn a_tunnel_whose_hello_carries_ech_is_closed_unforwarded() {
    let h = start(None, Limits::default());
    // encrypted_client_hello (0xfe0d) with a few payload bytes
    let ech = [0xfe, 0x0d, 0, 4, 0, 0, 1, 0];
    let (_, reply) = tunnel_with(&h, "allowed.test", &client_hello_with("allowed.test", &ech));
    assert_eq!(reply, "");
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(
        (rows[0].verdict, rows[0].rules.as_slice()),
        (Verdict::Deny, &["proxy-sni".to_owned()][..])
    );
    assert!(rows[0].reasons[0].contains("ECH"), "{:?}", rows[0].reasons);
}

#[test]
fn a_tunnel_that_is_not_tls_is_closed_unforwarded() {
    let h = start(None, Limits::default());
    let mut s = h.connect();
    write!(
        s,
        "CONNECT allowed.test:{} HTTP/1.1\r\n\r\nSSH-2.0-x\r\n",
        h.port()
    )
    .unwrap();
    let reply = read_all(&mut s);
    assert_eq!(reply, "HTTP/1.1 200 Connection Established\r\n\r\n");
    assert!(h.nothing_forwarded());
    assert_eq!(h.rows()[0].rules, ["proxy-sni"]);
}

#[test]
fn a_tunnel_to_an_address_that_is_not_tls_is_closed_unforwarded() {
    let h = start(None, Limits::default());
    let mut s = h.connect();
    // No SNI is required for an address, but a `ClientHello` still is.
    write!(
        s,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\nGET / HTTP/1.0\r\n\r\n",
        h.port()
    )
    .unwrap();
    let reply = read_all(&mut s);
    assert_eq!(reply, "HTTP/1.1 200 Connection Established\r\n\r\n");
    assert!(h.nothing_forwarded());
    assert_eq!(h.rows()[0].rules, ["proxy-sni"]);
}

#[test]
fn a_connection_that_cannot_be_recorded_is_refused() {
    let failing: &'static FailingRecorder = Box::leak(Box::default());
    let h = start(Some(failing), Limits::default());
    let reply = h.exchange(&format!(
        "GET http://allowed.test:{}/ HTTP/1.1\r\n\r\n",
        h.port()
    ));
    assert!(
        reply.starts_with("HTTP/1.1 403") && reply.contains("audit"),
        "{reply}"
    );
    let (_, reply) = tunnel(&h, "allowed.test", "allowed.test");
    assert_eq!(reply, "");
    // the upstream connection is opened before the record, but gets no bytes
    while let Ok(bytes) = h.received.recv_timeout(Duration::from_millis(300)) {
        assert!(bytes.is_empty());
    }
    // each failure is reported to the recorder, away from the failed log
    assert_eq!(
        *failing.0.lock().unwrap(),
        ["audit log unavailable: disk full"; 2]
    );
}

/// An allowed host is reached on 443, 80 and the ports its rules name
/// (`allowed.test:<upstream port>` here), and refused on any other.
#[test]
fn an_allowed_host_on_a_port_no_rule_names_is_refused() {
    let h = start(None, Limits::default());
    for port in [22, 8443] {
        let reply = h.exchange(&format!("CONNECT allowed.test:{port} HTTP/1.1\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 403"), "{port}: {reply}");
        assert!(reply.contains("proxy-port"), "{port}: {reply}");
    }
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.rules == ["proxy-port"]), "{rows:?}");
    // The port a rule names is served.
    let (_, reply) = tunnel(&h, "allowed.test", "allowed.test");
    assert_eq!(reply.as_bytes(), UPSTREAM_REPLY);
}
