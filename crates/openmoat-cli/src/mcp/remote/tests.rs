//! Remote MCP (ADR-127): the URL checks, the record, the event stream, the
//! sign-in metadata, the answer reader over an in-memory stream, and the
//! transport against a local server (the last binds a loopback port, which
//! some sandboxes refuse).

use std::io::{self, BufRead as _, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use openmoat_core::{EvalContext, Policy};
use serde_json::{Value, json};

use super::transport::{Transport, read_reply};
use super::{discovery, endpoint, sse};

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    }
}

fn transport(url: &str, policy: &str, token: Option<&str>) -> Transport {
    Transport::new(
        endpoint(url).unwrap(),
        token.map(|t| zeroize::Zeroizing::new(t.to_owned())),
        &Policy::parse(policy).unwrap(),
        ctx(),
        Box::new(openmoat_proxy::SystemResolver),
        Duration::from_secs(5),
    )
    .unwrap()
}

#[test]
fn urls_openmoat_never_sends_to_are_refused() {
    for bad in [
        "ftp://mcp.example.com/mcp",
        "https://user:pw@mcp.example.com/mcp",
        "https://mcp.example.com/mcp#frag",
        "http://mcp.example.com/mcp",
        "http://localhost:8931/mcp",
        "https://2852039166/mcp",
        "https://0xa9.0xfe.0xa9.0xfe/mcp",
        "https://metadata.google.internal/computeMetadata",
        "https://mcp.example.com /mcp",
    ] {
        assert!(endpoint(bad).is_err(), "{bad} must be refused");
    }
    for good in [
        "https://mcp.example.com/mcp",
        "https://mcp.example.com:8443/v1/mcp?tenant=a",
        "http://127.0.0.1:8931/mcp",
        "http://[::1]:8931/mcp",
    ] {
        assert!(endpoint(good).is_ok(), "{good} must be accepted");
    }
}

/// Every address is checked before a connection: a loopback, private or
/// link-local address the policy does not name is refused without one.
#[test]
fn unnamed_local_and_metadata_addresses_are_refused_before_connecting() {
    let policy = "version: 1\n";
    for url in [
        "http://127.0.0.1:9/mcp",
        "https://10.1.2.3/mcp",
        "https://100.100.100.200/mcp",
        "https://169.254.169.254/latest",
        "https://[fe80::1]/mcp",
    ] {
        let t = transport(url, policy, Some("tok"));
        let message = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let err = t.send(message).expect_err(url);
        let text = format!("{err:#}");
        assert!(
            text.contains("resolves to") || text.contains("never"),
            "{url}: {text}"
        );
        assert!(
            !text.contains("tok"),
            "the token must never be named: {text}"
        );
    }
}

#[test]
fn event_streams_give_whole_events_only() {
    let stream = b": ping\n\nid: 1\nevent: message\ndata: {\"a\":1}\n\ndata: {\"b\":\r\ndata: 2}\r\n\r\ndata: {\"cut\"";
    assert_eq!(sse::events(stream), ["{\"a\":1}", "{\"b\":\n2}"]);
    assert_eq!(sse::events(b"data:\n\n"), Vec::<String>::new());
    assert_eq!(
        sse::Kind::of("text/event-stream; charset=utf-8"),
        Some(sse::Kind::Events)
    );
    assert_eq!(sse::Kind::of("Application/JSON"), Some(sse::Kind::Json));
    assert_eq!(sse::Kind::of("text/html"), None);
}

#[test]
fn a_bearer_challenge_names_its_metadata() {
    let header = r#"Bearer error="invalid_token", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="a,b""#;
    assert_eq!(
        discovery::resource_metadata(header).as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    );
    assert_eq!(discovery::resource_metadata("Basic realm=x"), None);
    let server = endpoint("https://mcp.example.com/mcp").unwrap();
    assert_eq!(
        discovery::well_known(&server).unwrap().path,
        "/.well-known/oauth-protected-resource/mcp"
    );
    assert!(discovery::well_known(&endpoint("http://127.0.0.1:1/mcp").unwrap()).is_err());
}

#[test]
fn metadata_about_another_resource_or_with_a_plain_issuer_is_refused() {
    let server = endpoint("https://mcp.example.com/mcp").unwrap();
    let ok = json!({"resource": "https://mcp.example.com/mcp", "authorization_servers": ["https://auth.example.com"]});
    let read = discovery::check(&server, ok.to_string().as_bytes()).unwrap();
    assert_eq!(read.authorization_servers, ["https://auth.example.com"]);
    for bad in [
        json!({"resource": "https://evil.example/mcp"}),
        json!({"resource": "https://mcp.example.com/other"}),
        json!({"resource": "https://mcp.example.com/mcp", "authorization_servers": ["http://127.0.0.1:9"]}),
        json!({"resource": "https://mcp.example.com/mcp", "authorization_servers": ["javascript:alert(1)"]}),
    ] {
        assert!(
            discovery::check(&server, bad.to_string().as_bytes()).is_err(),
            "{bad}"
        );
    }
}

/// A stream that answers with canned bytes and keeps what was written.
struct Canned {
    answer: io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for Canned {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.answer.read(buf)
    }
}

impl Write for Canned {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canned(answer: &str) -> Canned {
    Canned {
        answer: io::Cursor::new(answer.as_bytes().to_vec()),
        written: Vec::new(),
    }
}

#[test]
fn answers_are_read_by_length_chunks_and_events() {
    let json =
        canned("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    let reply = read_reply(json, b"POST / HTTP/1.1\r\n\r\n", b"", None).unwrap();
    assert_eq!((reply.status, reply.body.as_slice()), (200, &b"{}"[..]));
    // An event stream the server leaves open ends at the response to the request.
    let events = canned(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n\
         1d\r\ndata: {\"id\":7,\"result\":{}}\n\n\r\n",
    );
    let reply = read_reply(events, b"", b"", Some(&json!(7))).unwrap();
    assert_eq!(sse::events(&reply.body), ["{\"id\":7,\"result\":{}}"]);
    let cut = canned("HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{}");
    assert!(read_reply(cut, b"", b"", None).is_err());
    let huge =
        canned("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab");
    assert!(read_reply(huge, b"", b"", None).is_err());
}

#[test]
fn a_failed_request_is_answered_and_a_notification_is_not() {
    let answer = super::failed_answer(
        r#"{"jsonrpc":"2.0","id":"a1","method":"tools/call"}"#,
        "cannot reach",
    )
    .unwrap();
    let v: Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(v["id"], "a1");
    assert_eq!(v["error"]["code"], -32603);
    assert!(
        super::failed_answer(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "x"
        )
        .is_none()
    );
}

/// One local server, named in the policy with its port: the session id and
/// protocol version from `initialize` come back on later requests, the
/// token is added, and an event stream's response is read (binds loopback).
#[test]
fn a_named_local_server_gets_the_token_and_its_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for (n, stream) in listener.incoming().take(2).enumerate() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            // Read the request's body before answering: a socket closed with
            // bytes still unread is reset on Windows, which can abort the
            // client's read of the answer (os error 10053).
            let length = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            seen.push(head);
            let answer = if n == 0 {
                let body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: s-42\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
                 data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n"
                    .to_owned()
            };
            stream.write_all(answer.as_bytes()).unwrap();
        }
        seen
    });
    let policy =
        format!("version: 1\nallow:\n  - {{ id: local-mcp, net: [\"127.0.0.1:{port}\"] }}\n");
    let t = transport(
        &format!("http://127.0.0.1:{port}/mcp"),
        &policy,
        Some("tok-1"),
    );
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    assert_eq!(t.send(init).unwrap().len(), 1);
    let list = t
        .send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    assert_eq!(list, [r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#]);
    let seen = server.join().unwrap();
    assert!(
        seen[0].contains("Authorization: Bearer tok-1"),
        "{}",
        seen[0]
    );
    assert!(!seen[0].contains("Mcp-Session-Id"), "{}", seen[0]);
    assert!(seen[1].contains("Mcp-Session-Id: s-42"), "{}", seen[1]);
    assert!(
        seen[1].contains("MCP-Protocol-Version: 2025-06-18"),
        "{}",
        seen[1]
    );
}
