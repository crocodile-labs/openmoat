use std::io::Cursor;
use std::net::Ipv4Addr;

use super::*;

#[test]
fn urls_keep_scheme_host_port_and_path() {
    let e = Endpoint::parse("https://Collector.Example:4318/v1/logs?x=1").unwrap();
    assert_eq!(
        e,
        Endpoint {
            scheme: Scheme::Https,
            host: "collector.example".to_owned(),
            port: 4318,
            path: "/v1/logs?x=1".to_owned(),
        }
    );
    let e = Endpoint::parse("https://siem.example").unwrap();
    assert_eq!((e.port, e.path.as_str()), (443, "/"));
    let e = Endpoint::parse("https://siem.example?a=b").unwrap();
    assert_eq!(e.path, "/?a=b");
    let e = Endpoint::parse("http://[::1]:4318/v1/logs").unwrap();
    assert_eq!(
        (e.host.as_str(), e.authority().as_str()),
        ("::1", "[::1]:4318")
    );
    assert_eq!(
        Endpoint::parse("http://localhost:8080/").unwrap().scheme,
        Scheme::Http
    );
}

#[test]
fn urls_that_could_leak_or_mislead_are_refused() {
    for url in [
        "http://siem.example/hook",
        "http://10.0.0.5/hook",
        "ftp://siem.example/",
        "https://user:pw@siem.example/",
        "https://siem.example/#frag",
        "https://siem.example/a b",
        "https://siem.example/\r\nX: y",
        "https://:443/",
        "https://siem.example:0/",
        "https://siem.example:99999/",
        "https://[not-v6]/",
        "https://siem_ex%61mple/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://x.metadata.goog./",
        "siem.example",
    ] {
        assert!(Endpoint::parse(url).is_err(), "{url}");
    }
}

#[test]
fn headers_cannot_change_the_framing() {
    let e = Endpoint::parse("https://siem.example/hook").unwrap();
    let head = request_head(&e, &[("X-Sig", "sha256=ab")], 12).unwrap();
    assert_eq!(
        String::from_utf8(head).unwrap(),
        "POST /hook HTTP/1.1\r\nHost: siem.example\r\nContent-Length: 12\r\n\
         Connection: close\r\nX-Sig: sha256=ab\r\n\r\n"
    );
    for (name, value) in [
        ("X-A", "v\r\nX-Injected: 1"),
        ("X-A", "v\n"),
        ("Bad Name", "v"),
        ("", "v"),
        ("Content-Length", "1"),
        ("transfer-encoding", "chunked"),
        ("Host", "other.example"),
    ] {
        assert!(request_head(&e, &[(name, value)], 1).is_err(), "{name}");
    }
}

/// A stream that answers `reply` and keeps what was written.
struct Scripted {
    reply: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // One byte at a time: the head must be put together across reads.
        let n = buf.len().min(1);
        self.reply.read(&mut buf[..n])
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn answer(reply: &str) -> Result<Answer, PostError> {
    let stream = Scripted {
        reply: Cursor::new(reply.as_bytes().to_vec()),
        written: Vec::new(),
    };
    exchange(stream, b"POST / HTTP/1.1\r\n\r\n", b"{}")
}

#[test]
fn the_answer_head_gives_status_and_retry_after() {
    let ok = answer("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
    assert!(ok.accepted() && !ok.retryable());
    let busy = answer("HTTP/1.1 429 Too Many\r\nRetry-After: 30\r\n\r\nbody").unwrap();
    assert_eq!(busy.retry_after_s, Some(30));
    assert!(busy.retryable() && !busy.accepted());
    let dated =
        answer("HTTP/1.1 503 Busy\r\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n").unwrap();
    assert_eq!(dated.retry_after_s, None);
    assert!(dated.retryable());
    for permanent in [301, 400, 401, 403, 404, 413, 501, 505] {
        let a = Answer {
            status: permanent,
            retry_after_s: None,
        };
        assert!(!a.retryable() && !a.accepted(), "{permanent}");
    }
    assert!(answer("HTTP/1.1 200 OK\r\n").is_err());
    assert!(answer("SSH-2.0-OpenSSH\r\n\r\n").is_err());
    let endless = format!("HTTP/1.1 200 OK\r\nX: {}\r\n", "a".repeat(MAX_HEAD));
    assert!(answer(&endless).is_err());
}

#[test]
fn metadata_link_local_and_plain_http_off_the_machine_are_refused() {
    let https = Endpoint::parse("https://siem.example/").unwrap();
    let http = Endpoint::parse("http://localhost:4318/").unwrap();
    let ip = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    assert!(check_address(&https, ip(169, 254, 169, 254)).is_err());
    assert!(check_address(&https, ip(100, 100, 100, 200)).is_err());
    assert!(check_address(&https, ip(0, 0, 0, 0)).is_err());
    assert!(check_address(&https, ip(10, 0, 0, 1)).is_ok());
    assert!(check_address(&https, ip(127, 0, 0, 1)).is_ok());
    assert!(check_address(&https, ip(203, 0, 113, 9)).is_ok());
    assert!(check_address(&http, ip(127, 0, 0, 1)).is_ok());
    assert!(check_address(&http, ip(10, 0, 0, 1)).is_err());
    assert!(check_address(&http, ip(203, 0, 113, 9)).is_err());
}
