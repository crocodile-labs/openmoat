//! The relay's protocol, each way it denies, and the service's two answers.
//! Over Unix socket pairs, so no port is bound.

use std::io::{Cursor, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;

use openmoat_audit::Store;
use openmoat_hosts::Host;

use super::client::exchange;
use super::service::RULE_TOKEN;
use super::wire::{NONCE_LEN, REPLY_MAGIC, REQUEST_MAGIC, Request};
use super::*;
use crate::home::Home;

const RUN: &str = "run-1-abcdef12";

/// The run's token, made at run time so no credential sits in the source; the
/// same for the whole test run.
fn token() -> &'static str {
    static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| random_hex(32).unwrap().to_string())
}

/// A request nonce made at run time, as the client makes one.
fn fresh_nonce() -> String {
    random_hex(NONCE_LEN / 2).unwrap().to_string()
}

impl Stream for UnixStream {
    fn set_timeouts(&self, limit: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(limit))?;
        self.set_write_timeout(Some(limit))
    }
}

fn request(token: &str, payload: &str) -> Request {
    Request {
        token: Zeroizing::new(token.as_bytes().to_vec()),
        nonce: fresh_nonce(),
        host: Host::ClaudeCode.id().to_owned(),
        cwd: "/p".to_owned(),
        continue_cli: true,
        payload: payload.to_owned(),
    }
}

fn reply(nonce: &str, code: u8) -> Reply {
    Reply {
        nonce: nonce.to_owned(),
        code,
        stdout: b"{\"hookSpecificOutput\":{}}\n".to_vec(),
        stderr: b"moat: trace 1\n".to_vec(),
    }
}

fn bytes_of(write: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out);
    out
}

#[test]
fn a_request_and_a_reply_read_back_as_written() {
    let sent = request(token(),"{\"tool_name\":\"Bash\"}");
    let wire = bytes_of(|out| sent.write_to(out).unwrap());
    assert!(wire.starts_with(REQUEST_MAGIC));
    assert_eq!(Request::read_from(&mut Cursor::new(&wire)).unwrap(), sent);
    let answer = reply(&sent.nonce, 2);
    let wire = bytes_of(|out| answer.write_to(out).unwrap());
    assert!(wire.starts_with(REPLY_MAGIC));
    let read = Reply::read_from(&mut Cursor::new(&wire), &sent.nonce).unwrap();
    assert_eq!(read, answer);
}

#[test]
fn an_oversize_payload_is_refused_before_it_is_read() {
    let limit = usize::try_from(MAX_PAYLOAD_BYTES).unwrap();
    let at_limit = request(token(),&"x".repeat(limit));
    let wire = bytes_of(|out| at_limit.write_to(out).unwrap());
    assert!(Request::read_from(&mut Cursor::new(&wire)).is_ok());
    let over = request(token(),&"x".repeat(limit + 1));
    let wire = bytes_of(|out| over.write_to(out).unwrap());
    let error = Request::read_from(&mut Cursor::new(&wire)).unwrap_err();
    assert!(
        format!("{error:#}").contains("larger than OpenMoat reads"),
        "{error:#}"
    );
    // A length past the limit is refused from its four bytes alone.
    let mut header = wire[..wire.len() - limit - 1 - 4].to_vec();
    header.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(Request::read_from(&mut Cursor::new(&header)).is_err());
}

#[test]
fn a_malformed_or_forged_reply_is_refused() {
    let (ours, theirs) = (fresh_nonce(), fresh_nonce());
    assert_ne!(ours, theirs);
    let nonce = ours.as_str();
    let good = bytes_of(|out| reply(nonce, 0).write_to(out).unwrap());
    let other_nonce = bytes_of(|out| reply(&theirs, 0).write_to(out).unwrap());
    let mut wrong_magic = good.clone();
    wrong_magic[0] = b'X';
    let truncated = good[..good.len() - 3].to_vec();
    let mut cases = vec![
        ("another request's nonce", other_nonce),
        ("wrong magic", wrong_magic),
        ("truncated", truncated),
        ("empty", Vec::new()),
        ("an HTTP answer", b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
    ];
    for code in [1u8, 3, 64, 255] {
        cases.push((
            "an exit code other than 0 or 2",
            bytes_of(|out| reply(nonce, code).write_to(out).unwrap()),
        ));
    }
    for (what, wire) in cases {
        assert!(
            Reply::read_from(&mut Cursor::new(&wire), nonce).is_err(),
            "{what} was accepted"
        );
    }
    assert!(Reply::read_from(&mut Cursor::new(&good), nonce).is_ok());
}

#[test]
fn a_request_that_is_not_one_is_refused() {
    let sent = request(token(),"{}");
    let mut short_nonce = sent.clone();
    short_nonce.nonce = "abc".to_owned();
    let mut not_hex = sent.clone();
    not_hex.nonce = "z".repeat(NONCE_LEN);
    for bad in [short_nonce, not_hex] {
        let wire = bytes_of(|out| bad.write_to(out).unwrap());
        assert!(Request::read_from(&mut Cursor::new(&wire)).is_err());
    }
    assert!(Request::read_from(&mut Cursor::new(b"GET / HTTP/1.1\r\n\r\n")).is_err());
}

#[test]
fn no_answer_in_time_is_an_error() {
    let (ours, _silent) = UnixStream::pair().unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(200);
    let error = exchange(ours, &request(token(),"{}"), deadline).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5), "{error:#}");
    // A deadline already past fails before anything is sent.
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    assert!(exchange(ours, &request(token(),"{}"), Instant::now()).is_err());
    let mut sent = Vec::new();
    theirs.read_to_end(&mut sent).unwrap();
    assert!(sent.is_empty(), "nothing was sent");
}

/// What [`configured`] makes of an environment holding `pairs`.
fn configured_with(pairs: &[(&str, &str)]) -> Option<Result<Endpoint>> {
    configured(&|var: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == var)
            .map(|(_, v)| (*v).to_owned())
    })
}

#[test]
fn the_environment_names_both_or_neither() {
    assert!(configured_with(&[]).is_none());
    for only_one in [(SOCKET_ENV, "127.0.0.1:9"), (TOKEN_ENV, "t")] {
        assert!(configured_with(&[only_one]).unwrap().is_err());
    }
    for socket in ["192.0.2.1:9", "/tmp/moat.sock", ""] {
        let pairs = [(SOCKET_ENV, socket), (TOKEN_ENV, "t")];
        assert!(configured_with(&pairs).unwrap().is_err(), "{socket}");
    }
    let empty_token = [(SOCKET_ENV, "127.0.0.1:9"), (TOKEN_ENV, "")];
    assert!(configured_with(&empty_token).unwrap().is_err());
    let good = [(SOCKET_ENV, "127.0.0.1:9"), (TOKEN_ENV, "t")];
    assert!(configured_with(&good).unwrap().is_ok());
}

/// A home with an empty audit log, and a stand-in for `moat` that prints the
/// variables the service sets, echoes its payload and exits with `code`.
fn service(code: i32) -> (tempfile::TempDir, Home, Service) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    Store::open(&home.audit_path()).unwrap();
    let moat = dir.path().join("moat");
    let script = format!(
        "#!/bin/sh\necho \"args=$*\"\necho \"run=$MOAT_RUN_SESSION socket=${{MOAT_GUARD_SOCKET-unset}}\"\n\
         cat\necho stderr-line >&2\nexit {code}\n"
    );
    std::fs::write(&moat, script).unwrap();
    std::fs::set_permissions(&moat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let service = Service::new(home.clone(), RUN, token().as_bytes(), PathBuf::from(&moat));
    (dir, home, service)
}

/// What the service answers to `sent`: the reply, or the error of a caller
/// that got none.
fn ask(service: &Service, sent: &Request) -> Result<Reply> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let server = std::thread::scope(|scope| {
        let handle = scope.spawn(|| service.answer(theirs));
        let reply = exchange(ours, sent, Instant::now() + Duration::from_secs(10));
        (reply, handle.join().unwrap())
    });
    server.0
}

#[test]
fn a_call_with_the_token_is_decided_outside_with_the_runs_session() {
    let (_dir, home, service) = service(0);
    let reply = ask(&service, &request(token(),"{\"payload\":1}")).unwrap();
    assert_eq!(reply.code, 0);
    let out = String::from_utf8(reply.stdout).unwrap();
    assert!(out.contains("args=guard --host claude-code"), "{out}");
    assert!(out.contains(&format!("run={RUN} socket=unset")), "{out}");
    assert!(out.contains("{\"payload\":1}"), "{out}");
    assert_eq!(reply.stderr, b"stderr-line\n");
    // The guard it started records; the service itself writes nothing.
    assert_eq!(home.open_audit().unwrap().count().unwrap(), 0);
}

#[test]
fn a_failing_guard_is_a_deny() {
    let (_dir, _home, service) = service(7);
    let reply = ask(&service, &request(token(),"{}")).unwrap();
    assert_eq!(reply.code, 2);
}

#[test]
fn a_wrong_token_gets_no_answer_and_is_recorded() {
    let (_dir, home, service) = service(0);
    // The run's token with its last character changed, so one byte differs.
    let mut near = token()[..token().len() - 1].to_owned();
    near.push(if token().ends_with('0') { '1' } else { '0' });
    for wrong in [near.as_str(), "", "x"] {
        let error = ask(&service, &request(wrong, "{}")).unwrap_err();
        assert!(format!("{error:#}").contains("answer"), "{error:#}");
    }
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(row.rules, [RULE_TOKEN]);
        assert_eq!(row.verdict, openmoat_core::Verdict::Deny);
        assert!(row.reasons[0].contains("claude-code"), "{:?}", row.reasons);
        assert!(!row.reasons[0].contains(token()));
    }
}

#[test]
fn random_hex_is_hex_of_the_length_asked_and_differs() {
    let (a, b) = (random_hex(32).unwrap(), random_hex(32).unwrap());
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(*a, *b);
}
