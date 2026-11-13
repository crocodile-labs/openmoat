//! The relay's protocol, each way it denies, and the service's two answers.
//! Over Unix socket pairs, so no port is bound.

use std::io::Cursor;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;

use openmoat_audit::Store;
use openmoat_hosts::Host;
use openmoat_proxy::coalesce::INTERVAL;

use super::client::{connect_retrying, exchange};
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
        caller_set: true,
        payload: payload.to_owned(),
        event: None,
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
    let sent = request(token(), "{\"tool_name\":\"Bash\"}");
    let wire = bytes_of(|out| sent.write_to(out).unwrap());
    assert!(wire.starts_with(REQUEST_MAGIC));
    assert_eq!(Request::read_from(&mut Cursor::new(&wire)).unwrap(), sent);
    let answer = reply(&sent.nonce, 2);
    let wire = bytes_of(|out| answer.write_to(out).unwrap());
    assert!(wire.starts_with(REPLY_MAGIC));
    let read = Reply::read_from(&mut Cursor::new(&wire), &sent.nonce).unwrap();
    assert_eq!(read, answer);
}

/// The event a hook's entry named (`guard --event`) reaches the run with the
/// payload, so the run reads the payload as that event's.
#[test]
fn the_entry_s_event_reads_back_and_a_request_without_one_has_none() {
    let mut sent = request(token(), "{\"toolName\":\"bash\"}");
    sent.event = Some("postToolUse".to_owned());
    let wire = bytes_of(|out| sent.write_to(out).unwrap());
    assert_eq!(Request::read_from(&mut Cursor::new(&wire)).unwrap(), sent);
    sent.event = Some("x".repeat(65));
    assert!(sent.write_to(&mut Vec::new()).is_err());
}

#[test]
fn an_oversize_payload_is_refused_before_it_is_read() {
    // Cline's payload carries the arguments twice: the relay takes the largest limit.
    let limit = super::wire::payload_limit();
    assert_eq!(limit as u64, 2 * MAX_PAYLOAD_BYTES);
    let at_limit = request(token(), &"x".repeat(limit));
    let wire = bytes_of(|out| at_limit.write_to(out).unwrap());
    assert!(Request::read_from(&mut Cursor::new(&wire)).is_ok());
    let over = request(token(), &"x".repeat(limit + 1));
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
    let sent = request(token(), "{}");
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
    let error = exchange(ours, &request(token(), "{}"), deadline).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5), "{error:#}");
    // A deadline already past fails before anything is sent.
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    assert!(exchange(ours, &request(token(), "{}"), Instant::now()).is_err());
    let mut sent = Vec::new();
    theirs.read_to_end(&mut sent).unwrap();
    assert!(sent.is_empty(), "nothing was sent");
}

/// A connect the sandbox refuses for a moment opens on a later try (#588);
/// one it keeps refusing, or any other failure, stays the error.
#[test]
fn only_a_brief_sandbox_refusal_is_connected_again() {
    use std::io::{Error, ErrorKind};
    let deadline = || Instant::now() + Duration::from_secs(5);
    let mut tries = 0;
    let opened = connect_retrying(
        |_| {
            tries += 1;
            if tries < 3 {
                Err(Error::from(ErrorKind::PermissionDenied))
            } else {
                Ok(tries)
            }
        },
        deadline(),
    );
    assert_eq!(opened.unwrap(), 3);
    let mut tries = 0;
    let refused = connect_retrying(
        |_| -> std::io::Result<()> {
            tries += 1;
            Err(Error::from(ErrorKind::PermissionDenied))
        },
        deadline(),
    );
    assert_eq!(refused.unwrap_err().kind(), ErrorKind::PermissionDenied);
    assert_eq!(tries, 10, "a lasting refusal is given up on");
    let mut tries = 0;
    let closed = connect_retrying(
        |_| -> std::io::Result<()> {
            tries += 1;
            Err(Error::from(ErrorKind::ConnectionRefused))
        },
        deadline(),
    );
    assert_eq!(closed.unwrap_err().kind(), ErrorKind::ConnectionRefused);
    assert_eq!(tries, 1, "nothing listening is not tried again");
    let past = connect_retrying(|_| Ok(()), Instant::now());
    assert_eq!(past.unwrap_err().kind(), ErrorKind::TimedOut);
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
    service_for(code, Some(Host::ClaudeCode))
}

/// [`service`] of a run whose program is `agent`'s (`None`: no agent OpenMoat knows).
fn service_for(code: i32, agent: Option<Host>) -> (tempfile::TempDir, Home, Service) {
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
    let service = Service::new(
        home.clone(),
        RUN,
        token().as_bytes(),
        PathBuf::from(&moat),
        agent,
    );
    (dir, home, service)
}

/// What the service answers to `sent`: the reply, or the error of a caller
/// that got none.
fn ask(service: &Service, sent: &Request) -> Result<Reply> {
    ask_at(service, sent, Instant::now)
}

/// [`ask`] of a service whose clock is `now`.
fn ask_at(service: &Service, sent: &Request, now: impl Fn() -> Instant + Send) -> Result<Reply> {
    // One at a time: macOS has no `pipe2`, so a stand-in started by one test
    // can inherit another's standard input before close-on-exec is set, and
    // both `cat`s then wait for an end of input that never comes.
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _turn = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (ours, theirs) = UnixStream::pair().unwrap();
    let server = std::thread::scope(|scope| {
        let handle = scope.spawn(|| service.answer_at(theirs, now));
        let reply = exchange(ours, sent, Instant::now() + Duration::from_secs(10));
        (reply, handle.join().unwrap())
    });
    server.0
}

#[test]
fn a_call_with_the_token_is_decided_outside_with_the_runs_session() {
    let (_dir, home, service) = service(0);
    let reply = ask(&service, &request(token(), "{\"payload\":1}")).unwrap();
    assert_eq!(reply.code, 0);
    let out = String::from_utf8(reply.stdout).unwrap();
    // `--relayed`: the call runs in the run's sandbox (ADR-039)
    assert!(
        out.contains("args=guard --host claude-code --relayed"),
        "{out}"
    );
    assert!(out.contains(&format!("run={RUN} socket=unset")), "{out}");
    assert!(out.contains("{\"payload\":1}"), "{out}");
    assert_eq!(reply.stderr, b"stderr-line\n");
    // The guard it started records; the service itself writes nothing.
    assert_eq!(home.open_audit().unwrap().count().unwrap(), 0);
}

#[test]
fn a_failing_guard_is_a_deny() {
    let (_dir, _home, service) = service(7);
    let reply = ask(&service, &request(token(), "{}")).unwrap();
    assert_eq!(reply.code, 2);
}

#[test]
fn a_wrong_token_gets_no_answer_and_is_recorded() {
    let (_dir, home, service) = service(0);
    // The run's token with its last character changed, so one byte differs.
    let mut near = token()[..token().len() - 1].to_owned();
    near.push(if token().ends_with('0') { '1' } else { '0' });
    // All three within one interval, however long the calls take to run: the
    // service's clock stands still.
    let at = Instant::now();
    for wrong in [near.as_str(), "", "x"] {
        let error = ask_at(&service, &request(wrong, "{}"), || at).unwrap_err();
        assert!(format!("{error:#}").contains("answer"), "{error:#}");
    }
    // The first has its row at once; the two after it, within the interval,
    // are counted, and recorded together when the run's service ends.
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].reasons[0].contains("claude-code"),
        "{:?}",
        rows[0].reasons
    );
    drop(service);
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].reasons[0].starts_with("2 hook calls came with a wrong token"));
    for row in rows {
        assert_eq!(row.rules, [RULE_TOKEN]);
        assert_eq!(row.verdict, openmoat_core::Verdict::Deny);
        assert!(!row.reasons[0].contains(token()));
    }
}

/// Wrong tokens from any local process cannot grow the log by one row each:
/// a flood is a row or two, and the run's own calls are still decided.
#[test]
fn a_flood_of_wrong_tokens_is_a_few_rows_and_the_run_still_decides() {
    let (_dir, home, service) = service(0);
    let started = Instant::now();
    for _ in 0..200 {
        assert!(ask(&service, &request("x", "{}")).is_err());
    }
    let reply = ask(&service, &request(token(), "{\"payload\":1}")).unwrap();
    assert_eq!(reply.code, 0);
    // One row at once, then at most one per interval while the flood lasts.
    let intervals = started.elapsed().as_secs() / INTERVAL.as_secs();
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    assert!(rows.len() as u64 <= 1 + intervals, "{} rows", rows.len());
    drop(service);
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    assert!(rows.len() as u64 <= 2 + intervals, "{} rows", rows.len());
    // Every refused call is in a row's count.
    let counted: u64 = rows
        .iter()
        .skip(1)
        .map(|r| {
            r.reasons[0]
                .split(' ')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum();
    assert_eq!(1 + counted, 200);
}

#[test]
fn random_hex_is_hex_of_the_length_asked_and_differs() {
    let (a, b) = (random_hex(32).unwrap(), random_hex(32).unwrap());
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(*a, *b);
}

mod scope;
