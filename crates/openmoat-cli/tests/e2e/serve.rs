//! `openmoat serve` (ADR-066) over a real loopback socket: the token on every
//! request, the `Host` check, read-only views that are exactly the commands'
//! JSON, and the refusals before it listens.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, ChildStdout, Stdio};

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, json, stderr};

/// A running `openmoat serve`, killed on drop.
struct Running {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    addr: SocketAddr,
    token: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `openmoat serve` as a person would and read the link it prints.
fn start(sb: &Sandbox) -> Running {
    let mut child = sb
        .command()
        .arg("serve")
        .env("MOAT_ASSUME_TTY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut link = None;
    for _ in 0..5 {
        let mut printed = String::new();
        if stdout.read_line(&mut printed).unwrap() == 0 {
            break;
        }
        if let Some(rest) = printed.trim().strip_prefix("http://") {
            link = Some(rest.to_owned());
            break;
        }
    }
    let link = link.expect("openmoat serve printed no link");
    let (addr, token) = link.split_once("/?token=").unwrap();
    Running {
        child,
        _stdout: stdout,
        addr: addr.parse().unwrap(),
        token: token.to_owned(),
    }
}

impl Running {
    /// The raw response to `head`.
    fn raw(&self, head: &str) -> String {
        let mut stream = TcpStream::connect(self.addr).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    /// `GET target` with the right `Host` and `headers`.
    fn get(&self, target: &str, headers: &str) -> String {
        self.raw(&format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\n{headers}\r\n",
            self.addr
        ))
    }

    /// The JSON body of `GET /api/<view>` with the token.
    fn api(&self, view: &str, query: &str) -> Value {
        let response = self.get(&format!("/api/{view}?{query}token={}", self.token), "");
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap()
    }
}

#[test]
fn serve_answers_only_with_the_token_and_shows_what_the_commands_print() {
    let sb = Sandbox::installed(&[".claude"]);
    sb.guard_bash("serve-1", &sb.project(), "cat ~/.ssh/id_rsa");
    sb.guard_bash("serve-1", &sb.project(), "ls");
    let server = start(&sb);
    assert_eq!(server.token.len(), 64);

    // Without the token, or with another, nothing is shown.
    for target in ["/", "/api/status", "/style.css", "/api/show"] {
        let response = server.get(target, "");
        assert!(
            response.starts_with("HTTP/1.1 401 "),
            "{target}: {response}"
        );
        assert!(!response.contains("id_rsa"), "{response}");
    }
    let wrong = "0".repeat(64);
    assert!(
        server
            .get(&format!("/api/show?token={wrong}"), "")
            .starts_with("HTTP/1.1 401 ")
    );

    // DNS rebinding: another name for this address is refused, token or not.
    let rebound = server.raw(&format!(
        "GET /api/show?token={} HTTP/1.1\r\nHost: evil.example:{}\r\n\r\n",
        server.token,
        server.addr.port()
    ));
    assert!(rebound.starts_with("HTTP/1.1 403 "), "{rebound}");
    let cross = server.get(
        &format!("/api/show?token={}", server.token),
        "Origin: http://evil.example\r\n",
    );
    assert!(cross.starts_with("HTTP/1.1 403 "), "{cross}");

    // Read-only: no other method, and no path for a command that changes state.
    let post = server.raw(&format!(
        "POST /api/show?token={} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
        server.token, server.addr
    ));
    assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
    let allow = server.get(&format!("/api/allow?token={}", server.token), "");
    assert!(allow.starts_with("HTTP/1.1 404 "), "{allow}");

    // The views are the commands' own JSON.
    let shown = server.api("show", "");
    assert_eq!(shown, json(&sb.moat(&["show", "--format", "json"])));
    assert!(shown.to_string().contains("secrets-paths"), "{shown}");
    let why = server.api("why", "");
    assert_eq!(why, json(&sb.moat(&["why", "--format", "json"])));
    let session = server.api("show", "session=serve-1&");
    assert_eq!(session.as_array().map(Vec::len), Some(2), "{session}");
    let status = server.api("status", "");
    assert!(status["agents"].is_array(), "{status}");
    let report = server.api("report", "since=all&");
    assert_eq!(
        report,
        json(&sb.moat(&["report", "--since", "all", "--format", "json"]))
    );

    // The page: strict headers, no cookie, no CORS, the token in its links only.
    let page = server.get(&format!("/?token={}", server.token), "");
    assert!(page.starts_with("HTTP/1.1 200 "), "{page}");
    assert!(
        page.contains("Content-Security-Policy: default-src 'none'"),
        "{page}"
    );
    assert!(page.contains("Referrer-Policy: no-referrer"), "{page}");
    let lower = page.to_ascii_lowercase();
    assert!(!lower.contains("set-cookie") && !lower.contains("access-control-"));
    assert!(!page.contains("<script"), "{page}");
    assert!(page.contains("secrets-paths"), "{page}");
}

#[test]
fn serve_refuses_any_address_but_loopback_and_a_missing_terminal() {
    let sb = Sandbox::installed(&[".claude"]);
    for listen in ["0.0.0.0:0", "[::]:0", "127.0.0.2:0"] {
        let mut cmd = sb.command();
        cmd.args(["serve", "--listen", listen])
            .env("MOAT_ASSUME_TTY", "1");
        let out = crate::common::output(&mut cmd, None);
        assert_eq!(out.status.code(), Some(USAGE), "{listen}");
        assert!(
            stderr(&out).contains("127.0.0.1 or [::1] only"),
            "{}",
            stderr(&out)
        );
    }
    // No terminal: a hook or a script.
    let out = sb.moat(&["serve"]);
    assert_ne!(out.status.code(), Some(OK));
    assert!(
        stderr(&out).contains("must be run by a person"),
        "{}",
        stderr(&out)
    );
}
