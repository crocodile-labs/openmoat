//! What an agent (or a server it reaches) might try inside a terminated
//! tunnel. Each request refused before the value goes in never reaches the
//! upstream: no connection is even opened.

use super::*;

/// Refused before the upstream was asked for: the agent got `status`, one row
/// with `rule`, and the upstream nothing.
fn refused_early(out: &Outcome, status: &str, rule: &str) {
    assert!(
        out.agent.starts_with(&format!("HTTP/1.1 {status} ")),
        "{}",
        out.agent
    );
    assert_eq!(out.connects, 0, "no connection to the upstream");
    assert!(out.upstream.is_empty(), "{}", out.upstream);
    assert_eq!(out.rules(), [rule], "{:?}", out.rows);
    out.kept_secret();
}

#[test]
fn a_method_or_path_the_rules_do_not_name_never_reaches_the_server() {
    let s = setup();
    for request in [
        format!(
            "DELETE /repos/o/r HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        get("/user/keys", ""),
        get("/repos", "").replace("GET /repos", "PUT /repos"),
        format!("POST /repos/o/r/pulls HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n"),
        // Without the placeholder the value still goes in, so the rules still apply.
        format!("GET /user HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
    ] {
        let out = exchange(&s, &request, OK);
        refused_early(&out, "403", "proxy-secret-route");
        assert!(
            out.rows[0].1.reasons[0].contains("matches none"),
            "{:?}",
            out.rows
        );
    }
}

#[test]
fn a_path_that_could_be_read_as_another_never_reaches_the_server() {
    let s = setup();
    for path in [
        "/repos/../user/keys",
        "/repos/o/../../user/keys",
        "/repos/%2e%2e/user/keys",
        "/repos/.%2E/user/keys",
        "/repos/%2E/x",
        "/repos/x%2f..%2fuser",
        "/repos/x%5c..%5cuser",
        "/repos/x/..;/user/keys",
        "/repos/%252e%252e/user",
        "/repos//user",
        "/repos/x%00",
    ] {
        let out = exchange(&s, &get(path, ""), OK);
        refused_early(&out, "403", "proxy-secret-route");
        assert!(
            !out.rows[0].1.reasons[0].contains("user"),
            "the reason does not quote the path"
        );
    }
    // Spellings the request parser refuses outright.
    for path in ["/repos\\..\\user", "/repos/x y"] {
        let out = exchange(&s, &get(path, ""), OK);
        assert_eq!(out.connects, 0, "{path}");
        assert!(out.upstream.is_empty(), "{path}");
        out.kept_secret();
    }
}

#[test]
fn a_method_override_never_reaches_the_server() {
    let s = setup();
    let post = |extra: &str, query: &str| {
        format!(
            "POST /repos/o/r/issues{query} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer \
             {PLACEHOLDER}\r\n{extra}Content-Length: 0\r\n\r\n"
        )
    };
    for request in [
        post("X-HTTP-Method-Override: DELETE\r\n", ""),
        post("x-http-method: DELETE\r\n", ""),
        post("X-Method-Override: PUT\r\n", ""),
        post("", "?_method=DELETE"),
        post("", "?a=1&%5Fmethod=DELETE"),
    ] {
        let out = exchange(&s, &request, OK);
        refused_early(&out, "403", "proxy-secret-route");
    }
}

#[test]
fn another_host_cannot_be_named_inside_the_tunnel() {
    let s = setup();
    for request in [
        // SNI and CONNECT say owner.test; the request asks the server for another.
        format!(
            "GET /repos/o HTTP/1.1\r\nHost: evil.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        format!("GET /repos/o HTTP/1.1\r\nHost: {HOST}:8443\r\n\r\n"),
        format!("GET /repos/o HTTP/1.1\r\nHost: {HOST}\r\nHost: evil.test\r\n\r\n"),
        "GET /repos/o HTTP/1.1\r\n\r\n".to_owned(),
        format!("GET https://evil.test/repos/o HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
        format!("GET https://{HOST}/repos/o HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
        "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n".to_owned(),
    ] {
        let out = exchange(&s, &request, OK);
        refused_early(&out, "400", "proxy-request");
    }
}

#[test]
fn a_second_request_on_the_tunnel_is_never_forwarded() {
    let s = setup();
    let second = "GET /repos/o HTTP/1.1\r\nHost: evil.test\r\n\r\n";
    let run = Run {
        after: second.as_bytes(),
        ..RUN
    };
    let out = exchange_with(&s, &get("/repos/o/r", ""), OK, &run);
    assert_eq!(
        out.upstream.matches("HTTP/1.1\r\n").count(),
        1,
        "{}",
        out.upstream
    );
    assert!(!out.upstream.contains("evil.test"), "{}", out.upstream);
    assert_eq!(
        out.agent.matches("HTTP/1.1 200").count(),
        1,
        "{}",
        out.agent
    );
    assert_eq!(out.rows.len(), 1, "{:?}", out.rows);
    // One that carries another host's placeholder is refused with the first.
    let leaking =
        format!("GET /repos/o HTTP/1.1\r\nHost: evil.test\r\nX-Key: {OTHER_PLACEHOLDER}\r\n\r\n");
    let run = Run {
        after: leaking.as_bytes(),
        ..RUN
    };
    let out = exchange_with(&s, &get("/repos/o/r", ""), OK, &run);
    assert!(!out.upstream.contains("evil.test"), "{}", out.upstream);
    out.kept_secret();
}

#[test]
fn another_secrets_placeholder_or_value_is_refused_here() {
    let s = setup();
    let out = exchange(
        &s,
        &get("/repos/o", &format!("X-Key: {OTHER_PLACEHOLDER}\r\n")),
        OK,
    );
    refused_early(&out, "403", "proxy-secret");
    assert!(
        out.rows[0].1.reasons[0].contains("secret `other`, which only other.test"),
        "{:?}",
        out.rows
    );
    // The value in a body, split across the chunked framing, is cut before it.
    let (a, b) = OTHER_VALUE.split_at(10);
    let request = format!(
        "POST /repos/o/r/issues HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         {:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    );
    let out = exchange(&s, &request, OK);
    assert!(!out.upstream.contains(OTHER_VALUE), "{}", out.upstream);
    assert!(
        out.rules().contains(&"proxy-secret".to_owned()),
        "{:?}",
        out.rows
    );
    out.kept_secret();
}

#[test]
fn ambiguous_request_framing_is_refused() {
    let s = setup();
    for framing in [
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked, chunked\r\n",
        "Content-Length: 4\r\nContent-Length: 5\r\n",
        "Transfer_Encoding: chunked\r\n",
    ] {
        let request =
            format!("POST /repos/o/r/issues HTTP/1.1\r\nHost: {HOST}\r\n{framing}\r\nbody");
        let out = exchange(&s, &request, OK);
        refused_early(&out, "400", "proxy-request");
    }
}

#[test]
fn an_answer_that_echoes_the_value_is_stopped_before_it() {
    let s = setup();
    let echo = |body: &str| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let (a, b) = VALUE.split_at(12);
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{{\"auth\":\"{a}\r\n{:x}\r\n{b}\"}}\r\n0\r\n\r\n",
        a.len() + 9,
        b.len() + 2
    );
    for reply in [
        echo(&format!("{{\"authorization\":\"Bearer {VALUE}\"}}")),
        echo(&format!("{}{VALUE}", "x".repeat(40_000))),
        chunked,
        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nyou sent {VALUE}"),
    ] {
        let out = exchange(&s, &get("/repos/o", ""), reply.as_bytes());
        out.kept_secret();
        assert!(
            out.rules().contains(&"proxy-secret".to_owned()),
            "{:?}",
            out.rows
        );
        // No released byte starts the value: at most a prefix shorter than it went out.
        assert!(
            !out.agent.contains(&VALUE[..VALUE.len() - 1]),
            "{}",
            out.agent
        );
    }
    // In the head, before anything was sent: a 502 with the reason.
    let header =
        format!("HTTP/1.1 401 Unauthorized\r\nX-Seen: Bearer {VALUE}\r\nContent-Length: 0\r\n\r\n");
    let out = exchange(&s, &get("/repos/o", ""), header.as_bytes());
    assert!(out.agent.starts_with("HTTP/1.1 502 "), "{}", out.agent);
    assert!(
        out.agent.contains("holds the value of secret `gh`"),
        "{}",
        out.agent
    );
    out.kept_secret();
}

#[test]
fn an_answer_the_proxy_cannot_read_is_refused() {
    let s = setup();
    for (reply, why) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc",
            "encoded",
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "transfer coding",
        ),
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            "switches protocols",
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
            "ambiguous",
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
            "ambiguous",
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
            "ambiguous",
        ),
    ] {
        let out = exchange(&s, &get("/repos/o", ""), reply.as_bytes());
        assert!(
            out.agent.starts_with("HTTP/1.1 502 "),
            "{reply}: {}",
            out.agent
        );
        assert!(out.agent.contains(why), "{reply}: {}", out.agent);
        assert!(!out.agent.contains("abc"), "{}", out.agent);
        out.kept_secret();
    }
}

#[test]
fn an_http_2_only_or_distrusting_client_never_gets_a_request_through() {
    let s = setup();
    let h2 = Run {
        alpn: &[b"h2"],
        ..RUN
    };
    let out = exchange_with(&s, &get("/repos/o", ""), OK, &h2);
    assert_eq!(out.connects, 0);
    assert_eq!(out.rules(), ["proxy-tls"], "{:?}", out.rows);
    assert!(
        out.rows[0].1.reasons[0].contains("HTTP/2"),
        "{:?}",
        out.rows
    );
    let other_ca = new_ca(&[HOST.to_owned()]).unwrap().cert_pem;
    let distrust = Run {
        agent_trusts: Some(&other_ca),
        ..RUN
    };
    let out = exchange_with(&s, &get("/repos/o", ""), OK, &distrust);
    assert_eq!(out.connects, 0);
    assert_eq!(out.rules(), ["proxy-tls"], "{:?}", out.rows);
    assert!(out.rows[0].1.reasons[0].contains("pins"), "{:?}", out.rows);
}

#[test]
fn an_upstream_whose_certificate_does_not_verify_never_gets_the_value() {
    let s = setup();
    // Signed by a CA the proxy does not trust, and one for another name.
    for upstream in [upstream_pki(HOST).1, upstream_pki("other.test").1] {
        let run = Run {
            upstream: Some(upstream),
            ..RUN
        };
        let out = exchange_with(&s, &get("/repos/o", ""), OK, &run);
        assert!(out.agent.starts_with("HTTP/1.1 502 "), "{}", out.agent);
        assert!(
            out.upstream.is_empty(),
            "nothing decrypted upstream: {}",
            out.upstream
        );
        assert_eq!(out.connects, 1);
        assert_eq!(out.rules(), ["proxy-tls"], "{:?}", out.rows);
        assert!(
            out.rows[0].1.reasons[0].contains("nothing was sent"),
            "{:?}",
            out.rows
        );
        out.kept_secret();
    }
}
