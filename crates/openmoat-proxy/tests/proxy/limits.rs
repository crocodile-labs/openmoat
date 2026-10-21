use super::*;

#[test]
fn oversized_and_malformed_heads_get_400() {
    let limits = Limits {
        max_head_bytes: 256,
        ..Limits::default()
    };
    let h = start(None, limits);
    let big = format!(
        "GET http://allowed.test/ HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(400)
    );
    assert!(h.exchange(&big).starts_with("HTTP/1.1 400"));
    assert!(
        h.exchange("GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            .starts_with("HTTP/1.1 400")
    );
    assert!(
        h.exchange("\x16\x03\x01\x00\x05hello")
            .starts_with("HTTP/1.1 400")
    );
    let rows = h.rows();
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|r| r.rules == ["proxy-request"] && r.dest.is_none())
    );
}

#[test]
fn connections_over_the_limit_get_503() {
    let limits = Limits {
        max_connections: 1,
        handshake_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let h = start(None, limits);
    let _held = h.connect(); // sends nothing, so it holds its slot
    // The proxy takes the slot when it accepts the held connection, which a
    // slow runner may not have done yet: ask again until it has, well inside
    // the handshake timeout that would free the slot.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let reply = loop {
        let reply = h.exchange("GET http://allowed.test/ HTTP/1.1\r\n\r\n");
        if reply.starts_with("HTTP/1.1 503") || std::time::Instant::now() > deadline {
            break reply;
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
}

#[test]
fn a_silent_client_is_dropped_after_the_handshake_timeout() {
    let limits = Limits {
        handshake_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let h = start(None, limits);
    let mut s = h.connect();
    s.write_all(b"GET http://allowed.test/ HT").unwrap();
    let reply = read_all(&mut s);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[test]
fn a_trickling_client_cannot_stretch_the_handshake_timeout() {
    let limits = Limits {
        handshake_timeout: Duration::from_millis(400),
        ..Limits::default()
    };
    let h = start(None, limits);
    let mut s = h.connect();
    let started = std::time::Instant::now();
    for byte in b"GET http://allowed.test/ HTTP/1.1\r\n" {
        if s.write_all(&[*byte]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
        if started.elapsed() > Duration::from_secs(1) {
            break;
        }
    }
    let reply = read_all(&mut s);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// A refusal at accept leaves a row, without one row per connection.
#[test]
fn refusals_at_accept_are_recorded_coalesced() {
    let limits = Limits {
        max_connections: 1,
        handshake_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let h = start(None, limits);
    let _held = h.connect();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut refused = 0;
    while std::time::Instant::now() < deadline && refused < 5 {
        if h.exchange("GET http://allowed.test/ HTTP/1.1\r\n\r\n")
            .starts_with("HTTP/1.1 503")
        {
            refused += 1;
        }
    }
    assert_eq!(refused, 5);
    let rows: Vec<Row> = h
        .rows()
        .into_iter()
        .filter(|r| r.rules == ["proxy-capacity"])
        .collect();
    assert_eq!(rows.len(), 1, "one row for the burst: {rows:?}");
    assert_eq!(rows[0].verdict, Verdict::Deny);
    assert!(
        rows[0].reasons[0].starts_with("1 connection refused"),
        "{rows:?}"
    );
}
