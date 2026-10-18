use std::fmt::Write as _;

use super::*;

fn ok(raw: &str) -> Request {
    parse(raw.as_bytes())
        .unwrap_or_else(|e| panic!("{raw:?}: {e}"))
        .unwrap_or_else(|| panic!("{raw:?}: incomplete"))
}

fn head(raw: &str) -> String {
    match ok(raw).target {
        Target::Http { head, .. } => String::from_utf8(head).unwrap(),
        Target::Connect { .. } => panic!("{raw:?} is a CONNECT"),
    }
}

#[test]
fn connect_targets_are_normalised() {
    for (raw, host, port) in [
        (
            "CONNECT Example.COM:443 HTTP/1.1\r\n\r\n",
            "example.com",
            443,
        ),
        (
            "CONNECT example.com.:8443 HTTP/1.1\r\n\r\n",
            "example.com",
            8443,
        ),
        ("CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "::1", 443),
        (
            "CONNECT [FD00:0EC2::0254]:80 HTTP/1.1\r\n\r\n",
            "fd00:ec2::254",
            80,
        ),
        ("CONNECT 10.0.0.1:22 HTTP/1.0\r\n\r\n", "10.0.0.1", 22),
    ] {
        let req = ok(raw);
        assert_eq!(req.method, "CONNECT");
        assert_eq!((req.host(), req.port()), (host, port), "{raw:?}");
        assert_eq!(req.head_len, raw.len());
    }
}

#[test]
fn bad_connect_targets_are_refused() {
    for raw in [
        "CONNECT example.com HTTP/1.1\r\n\r\n",
        "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
        "CONNECT example.com:99999 HTTP/1.1\r\n\r\n",
        "CONNECT user:pw@example.com:443 HTTP/1.1\r\n\r\n",
        "CONNECT ::1:443 HTTP/1.1\r\n\r\n",
        "CONNECT [fe80::1%en0]:443 HTTP/1.1\r\n\r\n",
        "CONNECT exa..mple.com:443 HTTP/1.1\r\n\r\n",
        "CONNECT :443 HTTP/1.1\r\n\r\n",
    ] {
        assert!(parse(raw.as_bytes()).is_err(), "{raw:?}");
    }
}

#[test]
fn partial_heads_ask_for_more() {
    assert_eq!(parse(b"CONNECT example.com:443 HTTP/1.1\r\n"), Ok(None));
    assert_eq!(parse(b"GET http://exa"), Ok(None));
    assert!(parse(b"\x16\x03\x01\x02\x00").is_err());
}

#[test]
fn plain_http_is_rewritten_to_origin_form() {
    let raw = "GET http://Example.com/a/b?q=1#frag HTTP/1.1\r\nHost: example.com\r\n\
               Proxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\n\
               Connection: keep-alive, X-Secret\r\nX-Secret: 1\r\nAccept: */*\r\n\r\nbody";
    let req = ok(raw);
    assert_eq!((req.host(), req.port()), ("example.com", 80));
    assert_eq!(&raw[req.head_len..], "body");
    assert_eq!(
        head(raw),
        "GET /a/b?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn proxy_credentials_are_kept_for_the_proxy_and_never_forwarded() {
    let raw = "GET http://example.com/ HTTP/1.1\r\nproxy-authorization: Basic c2Vzczp0b2s=\r\n\
               PROXY-AUTHORIZATION: Basic b3RoZXI=\r\n\r\n";
    let req = ok(raw);
    let values: Vec<&[u8]> = req.credentials.iter().map(AsRef::as_ref).collect();
    assert_eq!(values, [&b"Basic c2Vzczp0b2s="[..], &b"Basic b3RoZXI="[..]]);
    assert!(!head(raw).to_ascii_lowercase().contains("authorization"));
    // Never printed, so a panic or log line cannot show it.
    assert!(!format!("{req:?}").contains("c2Vzczp0b2s"));
    let tunnel = ok("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic eDp5\r\n\r\n");
    assert_eq!(tunnel.credentials.len(), 1);
    assert!(
        ok("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .credentials
            .is_empty()
    );
}

#[test]
fn a_missing_host_header_or_path_is_filled_in() {
    assert_eq!(
        head("GET http://example.com:8080 HTTP/1.0\r\n\r\n"),
        "GET / HTTP/1.0\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(
        head("HEAD http://example.com?x HTTP/1.1\r\n\r\n"),
        "HEAD /?x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn bodies_keep_their_framing() {
    let out = head(
        "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\n\r\n",
    );
    assert!(out.contains("Transfer-Encoding: chunked\r\n"), "{out}");
    assert!(!out.contains("TE:"), "{out}");
}

#[test]
fn ambiguous_or_unsupported_http_is_refused() {
    for raw in [
        // origin-form and https absolute-form are not proxied
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET https://example.com/ HTTP/1.1\r\n\r\n",
        // the Host header must name the same authority as the target
        "GET http://allowed.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "GET http://allowed.com/ HTTP/1.1\r\nHost: allowed.com:81\r\n\r\n",
        "GET http://allowed.com/ HTTP/1.1\r\nHost: allowed.com\r\nHost: allowed.com\r\n\r\n",
        // smuggling-shaped framing
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        // more than one Transfer-Encoding header on separate lines (TE.TE)
        "POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        // single Transfer-Encoding whose only token is not chunked
        "POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n",
        // comma-folded Transfer-Encoding whose token list is not exactly ["chunked"]
        "POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        "POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        // comma-folded Content-Length (CL smuggling): single header, list value
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: 10, 10\r\n\r\n",
        // signed, space-separated, hex Content-Length — none are a plain u64
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: +10\r\n\r\n",
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: 10 10\r\n\r\n",
        "POST http://a.com/ HTTP/1.1\r\nContent-Length: 0x0a\r\n\r\n",
        // credentials in the authority
        "GET http://u:p@a.com/ HTTP/1.1\r\n\r\n",
        // not HTTP/1.x
        "GET http://a.com/ HTTP/2.0\r\n\r\n",
    ] {
        assert!(parse(raw.as_bytes()).is_err(), "{raw:?}");
    }
}

#[test]
fn transfer_encoding_in_an_http_1_0_request_is_malformed() {
    for raw in [
        "POST http://a.com/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST http://a.com/ HTTP/1.0\r\ntransfer-encoding: chunked\r\nContent-Length: 4\r\n\r\n",
        "POST http://a.com/ HTTP/1.0\r\nTransfer-Encoding: identity\r\n\r\n",
    ] {
        assert!(
            matches!(parse(raw.as_bytes()), Err(RequestError::Malformed(_))),
            "{raw:?}"
        );
    }
    let length = ok("POST http://a.com/ HTTP/1.0\r\nContent-Length: 4\r\n\r\n");
    assert_eq!((length.host(), length.port()), ("a.com", 80));
    let chunked = ok("POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!((chunked.host(), chunked.port()), ("a.com", 80));
}

#[test]
fn well_formed_content_length_with_surrounding_whitespace_is_accepted() {
    // RFC 9112 §5.5 lets a receiver trim OWS around a header value; a plain
    // decimal integer is still a legitimate single length.
    let raw = "POST http://a.com/ HTTP/1.1\r\nContent-Length:  10 \r\n\r\n";
    let req = ok(raw);
    assert_eq!((req.host(), req.port()), ("a.com", 80));
}

#[test]
fn too_many_headers_are_refused() {
    let mut raw = String::from("GET http://a.com/ HTTP/1.1\r\n");
    for i in 0..=MAX_HEADERS {
        let _ = write!(raw, "X-{i}: v\r\n");
    }
    raw.push_str("\r\n");
    assert!(parse(raw.as_bytes()).is_err());
}

#[test]
fn names_are_checked_like_dns_labels() {
    assert_eq!(
        normalise_name("A-b_c.Example."),
        Some("a-b_c.example".to_owned())
    );
    assert_eq!(normalise_name("127.0.0.1"), Some("127.0.0.1".to_owned()));
    for bad in ["", ".", "a..b", "a b", "a/b", &"x".repeat(64), "é.com"] {
        assert_eq!(normalise_name(bad), None, "{bad:?}");
    }
}

#[test]
fn an_address_in_another_spelling_is_not_a_name() {
    // The system resolver reads these as IPv4 addresses; only the canonical
    // dotted form is an address here, and these are refused outright.
    for numeric in [
        "1572394766",
        "0x5d.0xb8.0xd7.0x0e",
        "0x5db8d70e",
        "0177.0.0.1",
        "127.1",
        "10.0.1",
        "0X7F.0.0.1",
    ] {
        assert_eq!(normalise_name(numeric), None, "{numeric:?}");
    }
    for name in [
        "1e100.net",
        "123.example.com",
        "0x.example",
        "v6.0x00.dev",
        "a1",
    ] {
        assert!(normalise_name(name).is_some(), "{name:?}");
    }
}
