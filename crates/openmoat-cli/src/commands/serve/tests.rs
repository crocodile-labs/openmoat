use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;

use super::response::Response;
use super::token::Token;
use super::{Server, address, page, request, routes};

const PORT: u16 = 41_234;

fn server() -> Server {
    Server {
        token: Token::fixed(&[0xab; 32]),
        port: PORT,
        open: AtomicUsize::new(0),
    }
}

fn token() -> String {
    "ab".repeat(32)
}

/// The answer to `head`, which must be complete.
fn answer(head: &str) -> Response {
    server().answer(head.as_bytes()).expect("a complete head")
}

fn get(target: &str, headers: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n{headers}\r\n")
}

fn body(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

#[test]
fn only_127_0_0_1_and_ipv6_loopback_are_listened_on() {
    for ok in ["127.0.0.1:0", "127.0.0.1:8080", "[::1]:0"] {
        let addr: SocketAddr = ok.parse().unwrap();
        assert_eq!(address::check(addr).unwrap(), addr, "{ok}");
    }
    for refused in [
        "0.0.0.0:0",
        "[::]:0",
        "127.0.0.2:0",
        "192.168.1.10:8080",
        "10.0.0.1:0",
        "[::ffff:127.0.0.1]:0",
        "[fe80::1]:0",
    ] {
        let error = address::check(refused.parse().unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("127.0.0.1 or [::1] only"),
            "{refused}"
        );
    }
}

#[test]
fn a_token_is_32_random_bytes_as_hex_and_matches_only_itself() {
    let a = Token::generate().unwrap();
    let b = Token::generate().unwrap();
    assert_eq!(a.as_str().len(), 64);
    assert!(a.as_str().bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a.as_str(), b.as_str());
    assert!(a.matches(a.as_str()));
    assert!(!a.matches(b.as_str()));
    assert!(!a.matches(""));
    assert!(!a.matches(&a.as_str()[..63]));
    assert!(!a.matches(&format!("{}0", a.as_str())));
    assert_eq!(format!("{a:?}"), "Token(..)");
}

#[test]
fn every_request_needs_the_token() {
    assert_eq!(answer(&get("/style.css", "")).status, 401);
    assert_eq!(answer(&get("/api/status", "")).status, 401);
    let wrong = "cd".repeat(32);
    assert_eq!(
        answer(&get(&format!("/style.css?token={wrong}"), "")).status,
        401
    );
    assert_eq!(answer(&get("/style.css?token=", "")).status, 401);
    let short = &token()[..10];
    assert_eq!(
        answer(&get(&format!("/style.css?token={short}"), "")).status,
        401
    );
    let in_query = answer(&get(&format!("/style.css?token={}", token()), ""));
    assert_eq!(in_query.status, 200, "{}", body(&in_query));
    let bearer = format!("Authorization: Bearer {}\r\n", token());
    assert_eq!(answer(&get("/style.css", &bearer)).status, 200);
    let both = answer(&get(&format!("/style.css?token={}", token()), &bearer));
    assert_eq!(both.status, 400);
    let basic = format!("Authorization: Basic {}\r\n", token());
    assert_eq!(answer(&get("/style.css", &basic)).status, 401);
}

#[test]
fn a_401_names_no_token_and_says_where_it_is() {
    let refused = answer(&get("/api/status", ""));
    assert!(!body(&refused).contains(&token()));
    assert!(body(&refused).contains("link `openmoat serve` printed"));
    let mut wire = Vec::new();
    refused.write_to(&mut wire).unwrap();
    assert!(
        String::from_utf8(wire)
            .unwrap()
            .contains("WWW-Authenticate: Bearer\r\n")
    );
}

/// DNS rebinding: a page on `evil.example` that makes its name resolve to
/// 127.0.0.1 sends its own name as the `Host`.
#[test]
fn a_host_header_that_is_not_a_loopback_name_of_this_port_is_refused() {
    let t = token();
    for host in [
        format!("evil.example:{PORT}"),
        "evil.example".to_owned(),
        "127.0.0.1".to_owned(),
        format!("127.0.0.1:{}", PORT + 1),
        format!("127.0.0.2:{PORT}"),
        format!("localhost.evil.example:{PORT}"),
        format!("0.0.0.0:{PORT}"),
    ] {
        let head = format!("GET /style.css?token={t} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(answer(&head).status, 403, "{host}");
    }
    let none = format!("GET /style.css?token={t} HTTP/1.1\r\n\r\n");
    assert_eq!(answer(&none).status, 403);
    for host in [
        format!("127.0.0.1:{PORT}"),
        format!("localhost:{PORT}"),
        format!("LocalHost:{PORT}"),
        format!("[::1]:{PORT}"),
    ] {
        let head = format!("GET /style.css?token={t} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(answer(&head).status, 200, "{host}");
    }
    let twice = format!(
        "GET /style.css?token={t} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nHost: evil.example\r\n\r\n"
    );
    assert_eq!(answer(&twice).status, 400);
}

#[test]
fn port_80_also_takes_the_bare_names() {
    assert!(address::host_names(80).contains(&"localhost".to_owned()));
    assert!(!address::host_names(8080).contains(&"localhost".to_owned()));
}

#[test]
fn a_request_from_another_site_is_refused_even_with_the_token() {
    let target = format!("/style.css?token={}", token());
    for header in [
        "Origin: http://evil.example\r\n".to_owned(),
        "Origin: null\r\n".to_owned(),
        format!("Origin: https://127.0.0.1:{PORT}\r\n"),
        "Sec-Fetch-Site: cross-site\r\n".to_owned(),
        "Sec-Fetch-Site: same-site\r\n".to_owned(),
    ] {
        assert_eq!(answer(&get(&target, &header)).status, 403, "{header}");
    }
    for header in [
        format!("Origin: http://127.0.0.1:{PORT}\r\n"),
        "Sec-Fetch-Site: same-origin\r\n".to_owned(),
        "Sec-Fetch-Site: none\r\n".to_owned(),
    ] {
        assert_eq!(answer(&get(&target, &header)).status, 200, "{header}");
    }
}

#[test]
fn only_a_get_without_a_body_is_served() {
    let t = token();
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
        let head =
            format!("{method} /api/status?token={t} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n");
        let refused = answer(&head);
        assert_eq!(refused.status, 405, "{method}");
        let mut wire = Vec::new();
        refused.write_to(&mut wire).unwrap();
        assert!(String::from_utf8(wire).unwrap().contains("Allow: GET\r\n"));
    }
    let with_body = get(&format!("/api/status?token={t}"), "Content-Length: 4\r\n");
    assert_eq!(answer(&with_body).status, 400);
    let chunked = get(
        &format!("/api/status?token={t}"),
        "Transfer-Encoding: chunked\r\n",
    );
    assert_eq!(answer(&chunked).status, 400);
}

#[test]
fn a_malformed_or_partial_head_is_refused_or_waited_for() {
    assert!(server().answer(b"GET / HTTP/1.1\r\nHost: 127").is_none());
    assert_eq!(answer("GET\x01 / HTTP/1.1\r\n\r\n").status, 400);
    let t = token();
    for query in ["a=%zz", "a=%2", "a=%+1", "a=1&a=2", "a=%ff%fe"] {
        assert_eq!(
            answer(&get(&format!("/show?{query}&token={t}"), "")).status,
            400,
            "{query}"
        );
    }
    let two_tokens = get(&format!("/style.css?token={t}&token={t}"), "");
    assert_eq!(answer(&two_tokens).status, 400);
}

#[test]
fn unknown_paths_and_parameters_are_refused_before_anything_is_read() {
    let t = token();
    for target in [
        "/admin",
        "/api/",
        "/api/style.css",
        "/api/allow",
        "/show/1",
        "/../status",
    ] {
        assert_eq!(
            answer(&get(&format!("{target}?token={t}"), "")).status,
            404,
            "{target}"
        );
    }
    for target in [
        "/show?id=1&session=s",
        "/show?since=7d&id=1",
        "/show?recent=1001",
        "/show?recent=x",
        "/report?host=nope",
        "/why?last=1",
        "/status?format=text",
        "/style.css?x=1",
    ] {
        let response = answer(&get(&format!("{target}&token={t}"), ""));
        assert_eq!(response.status, 400, "{target}: {}", body(&response));
    }
}

#[test]
fn views_take_the_parameters_their_commands_take() {
    let parse = |target: &str| {
        let head = get(target, "");
        let req = request::parse(head.as_bytes()).unwrap().unwrap();
        routes::route(&req).unwrap()
    };
    let routes::Target::View {
        view: routes::View::Show(args),
        api: true,
    } = parse("/api/show?session=a%20b&recent=5")
    else {
        panic!("not /api/show");
    };
    assert_eq!(args.session.as_deref(), Some("a b"));
    assert_eq!(args.recent, 5);
    let routes::Target::View {
        view: routes::View::Report(args),
        api: false,
    } = parse("/report?since=24h&host=codex")
    else {
        panic!("not /report");
    };
    assert_eq!(args.since, "24h");
    assert_eq!(args.host.map(openmoat_hosts::Host::id), Some("codex"));
    let routes::Target::View {
        view: routes::View::Why(which),
        ..
    } = parse("/why?event=1f")
    else {
        panic!("not /why");
    };
    assert_eq!(which.as_deref(), Some("1f"));
    assert!(matches!(
        parse("/"),
        routes::Target::View {
            view: routes::View::Status,
            api: false
        }
    ));
}

#[test]
fn every_response_carries_the_strict_headers_and_no_cookie_or_cors() {
    let mut wire = Vec::new();
    answer(&get(&format!("/style.css?token={}", token()), ""))
        .write_to(&mut wire)
        .unwrap();
    let text = String::from_utf8(wire).unwrap();
    for header in [
        "Content-Security-Policy: default-src 'none'; style-src 'self'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'\r\n",
        "Cache-Control: no-store\r\n",
        "Referrer-Policy: no-referrer\r\n",
        "X-Content-Type-Options: nosniff\r\n",
        "X-Frame-Options: DENY\r\n",
        "Connection: close\r\n",
        "Content-Type: text/css; charset=utf-8\r\n",
    ] {
        assert!(text.contains(header), "{header}");
    }
    let lower = text.to_ascii_lowercase();
    assert!(!lower.contains("set-cookie"));
    assert!(!lower.contains("access-control-"));
}

#[test]
fn text_from_the_log_is_escaped_and_cleaned() {
    assert_eq!(
        page::shown("<script>alert('x')</script> \"&\u{202e}"),
        "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &quot;&amp;?"
    );
    let t = Token::fixed(&[1; 32]);
    let link = page::href("/show", &[("session", "a\"><script>&b")], &t);
    assert!(!link.contains('"') && !link.contains('<'), "{link}");
    assert!(link.starts_with("/show?session=a%22%3E%3Cscript%3E%26b&amp;token=0101"));
    let html = page::page("x<y", "<p>b</p>", "/api/status?token=0", &t);
    assert!(html.contains("<title>OpenMoat · x&lt;y</title>"));
    assert!(!html.contains("<script"));
}

#[test]
fn query_values_round_trip_through_the_encoding() {
    for value in ["a b", "x&y=z", "ü/%", "plain-._~"] {
        let head = get(&format!("/why?event={}", request::encode(value)), "");
        let req = request::parse(head.as_bytes()).unwrap().unwrap();
        assert_eq!(req.param("event"), Some(value));
    }
}
