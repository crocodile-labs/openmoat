//! The MCP gateway (ADR-045) through the real binary: `openmoat mcp proxy`
//! in front of a server that records every byte it receives
//! (`mcp_gateway/recording_server.py`). A call OpenMoat denies, a call the hook
//! never decided, a call a host that cannot ask was refused, a held tool's
//! call and a changed tool's call leave nothing in the record; an allowed call
//! arrives unchanged, once, and its audit row names the hook's session. The
//! relay's fixtures (`mcp_gateway/fixtures.json`) run here too, host side.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common::{OK, Sandbox, output, stdout, text};

const FIXTURES: &str = include_str!("mcp_gateway/fixtures.json");

/// Every place a reader may end a line (as in `src/mcp/relay/tests/gaps.rs`).
const LINE_BREAKS: [char; 5] = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];

fn server_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/mcp_gateway/recording_server.py")
}

/// An installed home whose MCP server `docs` has had its tools accepted.
struct Gateway {
    sb: Sandbox,
    record: PathBuf,
}

impl Gateway {
    fn new() -> Self {
        let sb = Sandbox::installed(&[".claude"]);
        let record = sb.home.join("record.jsonl");
        let gateway = Self { sb, record };
        let listed = gateway.session("answer", &[list(1)]);
        assert!(
            listed.contains(r#""tools":[]"#),
            "a new server is held: {listed}"
        );
        let accepted = gateway.sb.moat_approving(&["mcp", "accept", "docs"]);
        assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
        let listed = gateway.session("answer", &[list(1)]);
        assert!(listed.contains("Accepted."), "{listed}");
        gateway.forget();
        gateway
    }

    fn proxy(&self, mode: &str) -> std::process::Command {
        let mut command = self.sb.command();
        command
            .args(["mcp", "proxy", "--server", "docs", "--", "python3"])
            .arg(server_script())
            .arg(&self.record)
            .arg(mode);
        command
    }

    /// One session: `lines` from the host, all at once; what the host got.
    fn session(&self, mode: &str, lines: &[String]) -> String {
        let input: String = lines.iter().flat_map(|l| [l.as_str(), "\n"]).collect();
        let out = output(&mut self.proxy(mode), Some(&input));
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        stdout(&out)
    }

    /// What reached the server so far.
    fn recorded(&self) -> String {
        std::fs::read_to_string(&self.record).unwrap_or_default()
    }

    /// The messages that reached the server, each piece cut at every line
    /// break and read as one whole message.
    fn received(&self) -> Vec<Value> {
        self.recorded()
            .split(LINE_BREAKS)
            .filter(|p| !p.trim().is_empty())
            .map(|p| serde_json::from_str(p).unwrap_or_else(|e| panic!("{e}: {p:?}")))
            .collect()
    }

    /// The tool calls that reached the server.
    fn calls(&self) -> Vec<Value> {
        self.received()
            .into_iter()
            .flat_map(|m| match m {
                Value::Array(batch) => batch,
                one => vec![one],
            })
            .filter(|m| m["method"] == "tools/call")
            .collect()
    }

    fn forget(&self) {
        let _ = std::fs::remove_file(&self.record);
    }

    /// The verdict `host`'s hook (Claude Code's or Codex's) gives
    /// `mcp__docs__<tool>` with `arguments` in `session`.
    fn hook(&self, host: &str, session: &str, tool: &str, arguments: &Value) -> String {
        self.hook_in(host, session, tool, arguments, "default")
    }

    /// [`Gateway::hook`] in Claude Code permission mode `mode`.
    fn hook_in(
        &self,
        host: &str,
        session: &str,
        tool: &str,
        arguments: &Value,
        mode: &str,
    ) -> String {
        let payload = json!({
            "session_id": session, "cwd": self.sb.project().to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": format!("mcp__docs__{tool}"),
            "tool_input": arguments, "tool_use_id": format!("{session}-{tool}"),
            "permission_mode": mode
        });
        let out = self.sb.guard(host, &payload.to_string());
        let answer: Value = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
        answer["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or(if out.status.code() == Some(2) {
                "deny"
            } else {
                "defer"
            })
            .to_owned()
    }

    /// The audit rows the proxy left.
    fn proxy_rows(&self) -> Vec<Value> {
        let out = self.sb.moat(&["audit", "export"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        stdout(&out)
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|row| row["host"] == "mcp-proxy")
            .collect()
    }
}

fn list(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}).to_string()
}

fn call(id: u64, tool: &str, arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
    .to_string()
}

/// The answer to request `id` among what the host got.
fn answer(host: &str, id: u64) -> Value {
    host.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|m| m["id"] == id)
        .unwrap_or_else(|| panic!("no answer to {id}: {host}"))
}

#[test]
fn an_allowed_call_arrives_unchanged_once_and_names_the_hooks_session() {
    let gw = Gateway::new();
    let arguments =
        json!({"q": "rust \u{e9}\u{2028}", "limit": 9_007_199_254_740_993_u64, "ratio": 0.1});
    assert_ne!(gw.hook("claude-code", "s-42", "search", &arguments), "deny");
    let host = gw.session(
        "answer",
        &[call(7, "search", &arguments), call(8, "search", &arguments)],
    );
    assert_eq!(
        answer(&host, 7)["result"]["content"][0]["text"],
        "called search"
    );
    let calls = gw.calls();
    assert_eq!(
        calls.len(),
        1,
        "one decision lets one call through: {calls:?}"
    );
    assert_eq!(calls[0]["params"]["arguments"], arguments, "unchanged");
    let refused = answer(&host, 8);
    assert_eq!(refused["error"]["code"], -32001, "{refused}");
    assert!(
        refused.to_string().contains("mcp-unattributed"),
        "{refused}"
    );

    let rows = gw.proxy_rows();
    let passed = rows
        .iter()
        .find(|r| r["verdict"] == "allow")
        .expect("a passed row");
    assert_eq!(passed["session_id"], "s-42", "{passed}");
    assert_eq!(passed["call_id"], "s-42-search", "{passed}");
    assert_eq!(passed["tool"], "mcp__docs__search");
}

#[test]
fn a_call_the_hook_never_decided_never_reaches_the_server() {
    let gw = Gateway::new();
    let checked = json!({"q": "rust"});
    assert_ne!(gw.hook("claude-code", "s1", "search", &checked), "deny");
    // Other arguments than the hook checked, or no hook at all.
    let host = gw.session(
        "answer",
        &[
            call(1, "search", &json!({"q": "rust", "extra": 1})),
            call(2, "search", &json!({})),
        ],
    );
    for id in [1, 2] {
        assert!(
            answer(&host, id).to_string().contains("mcp-unattributed"),
            "{host}"
        );
    }
    assert!(gw.calls().is_empty(), "{}", gw.recorded());
}

#[test]
fn a_call_the_policy_denies_never_reaches_the_server() {
    let gw = Gateway::new();
    let key = json!({"path": gw.sb.home.join(".ssh/id_ed25519").to_string_lossy()});
    assert_eq!(gw.hook("claude-code", "s1", "read_file", &key), "deny");
    let url = json!({"url": "https://collector.example.net/upload"});
    assert_eq!(gw.hook("claude-code", "s1", "fetch", &url), "deny");
    let host = gw.session(
        "answer",
        &[call(1, "read_file", &key), call(2, "fetch", &url)],
    );
    let denied = answer(&host, 1).to_string();
    assert!(
        denied.contains("secrets-paths"),
        "the proxy decides on the arguments too: {denied}"
    );
    assert!(
        answer(&host, 2).to_string().contains("default.net"),
        "{host}"
    );
    assert!(gw.calls().is_empty(), "{}", gw.recorded());
    let rows = gw.proxy_rows();
    assert!(rows.iter().all(|r| r["verdict"] == "deny"), "{rows:?}");
}

#[test]
fn a_call_asked_after_a_secret_read_and_refused_never_reaches_the_server() {
    let gw = Gateway::new();
    // A policy that asks for secret reads, so one can run and taint the session.
    let policy = gw.sb.home.join(".moat/policy.yaml");
    let now = std::fs::read_to_string(&policy).unwrap();
    std::fs::write(
        &policy,
        now.replacen(
            "deny:\n",
            "ask:\n  - id: secrets-paths\n    fs.read: ['~/.ssh/**']\ndeny:\n",
            1,
        ),
    )
    .unwrap();
    let accept = gw.sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accept).contains("re-pinned"), "{}", text(&accept));
    let read = json!({"file_path": gw.sb.home.join(".ssh/id_rsa").to_string_lossy()});
    let payload = json!({"session_id": "k1", "cwd": gw.sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": read, "tool_use_id": "r1"});
    let asked = gw.sb.guard("claude-code", &payload.to_string());
    assert!(stdout(&asked).contains(r#""ask""#), "{}", text(&asked));
    let search = json!({"q": "anything"});
    // The session read a secret, so its MCP calls ask; in a mode where no
    // person sees the question the ask is a deny, which no call gets past.
    assert_eq!(
        gw.hook_in("claude-code", "k1", "search", &search, "dontAsk"),
        "deny"
    );
    // Asked in another session it is a question the person refuses: the host
    // then sends nothing, and the clean session is still allowed.
    let clean = json!({"q": "clean"});
    assert_ne!(gw.hook("claude-code", "k2", "search", &clean), "deny");
    let host = gw.session(
        "answer",
        &[call(1, "search", &search), call(2, "search", &clean)],
    );
    assert_eq!(
        answer(&host, 2)["result"]["content"][0]["text"],
        "called search",
        "{host}"
    );
    assert!(
        answer(&host, 1).to_string().contains("mcp-unattributed"),
        "{host}"
    );
    assert_eq!(
        gw.calls().len(),
        1,
        "only the clean session's call: {}",
        gw.recorded()
    );
    let rows = gw.proxy_rows();
    let passed: Vec<&Value> = rows.iter().filter(|r| r["verdict"] == "allow").collect();
    assert_eq!(passed.len(), 1, "{rows:?}");
    assert_eq!(
        passed[0]["session_id"], "k2",
        "the call is the clean session's"
    );
}

#[test]
fn a_held_tool_and_a_tool_that_changed_mid_session_never_reach_the_server() {
    let gw = Gateway::new();
    let arguments = json!({});
    for _ in 0..3 {
        assert_ne!(gw.hook("claude-code", "s1", "search", &arguments), "deny");
    }
    let mut live = Live::start(&gw, "rug");
    let first = live.ask(&call(1, "search", &arguments), 1);
    assert_eq!(
        first["result"]["content"][0]["text"], "called search",
        "{first}"
    );
    // The server changed `search` and said so; the relay reads the tools
    // again, and holds the changed one although the host never lists again.
    let deadline = Instant::now() + Duration::from_secs(20);
    let held = loop {
        let reply = live.ask(&call(2, "search", &arguments), 2);
        // While the relay reads the tools again it asks the host to retry.
        let held = reply.to_string().contains("openmoat mcp accept docs");
        if held || Instant::now() > deadline {
            break reply;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(held["error"]["code"], -32602, "{held}");
    assert!(
        held.to_string().contains("openmoat mcp accept docs"),
        "{held}"
    );
    live.end();
    assert_eq!(gw.calls().len(), 1, "{}", gw.recorded());
    assert!(
        gw.recorded().contains("openmoat-relay-"),
        "the relay listed the tools itself"
    );
    // A tool never accepted: refused whatever the hook said.
    assert_ne!(gw.hook("claude-code", "s1", "rm_rf", &arguments), "deny");
    gw.forget();
    let host = gw.session("answer", &[call(3, "rm_rf", &arguments)]);
    assert_eq!(answer(&host, 3)["error"]["code"], -32602, "{host}");
    assert!(gw.calls().is_empty(), "{}", gw.recorded());
}

/// The relay's fixtures, host side, through the binary: each call of the
/// accepted tool first gets a hook decision, as a host would ask for one.
#[test]
fn the_relay_fixtures_hold_through_the_binary() {
    let gw = Gateway::new();
    let all: Value = serde_json::from_str(FIXTURES).unwrap();
    let fixtures = ["attacks", "benign"]
        .iter()
        .flat_map(|kind| all[*kind].as_array().unwrap().clone());
    for fixture in fixtures {
        let steps = fixture["steps"].as_array().unwrap();
        // An attack the server plays a part in needs that server; the host's
        // side of normal use runs against one that answers nothing.
        let serves = steps.iter().any(|s| s.get("server").is_some());
        let attack = fixture.get("server_never_calls").is_some()
            || fixture.get("host_never_lists").is_some()
            || fixture.get("host_must_not_contain").is_some();
        if (serves && attack) || fixture.get("pins").is_some() {
            continue;
        }
        let id = fixture["id"].as_str().unwrap();
        let lines: Vec<String> = steps
            .iter()
            .filter_map(|s| s["host"].as_str().map(str::to_owned))
            .collect();
        for line in &lines {
            decide_like_a_host(&gw, line);
        }
        gw.forget();
        gw.session("silent", &lines);
        let received = gw.received();
        let recorded = gw.recorded();
        for call in gw.calls() {
            assert_eq!(call["params"]["name"], "search", "{id}: {recorded}");
        }
        for text in fixture["server_must_not_contain"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let text = text.as_str().unwrap();
            assert!(
                !recorded.contains(text),
                "{id}: {text:?} reached the server: {recorded}"
            );
        }
        if let Some(expected) = fixture.get("server_receives") {
            assert_eq!(&Value::Array(received), expected, "{id}");
        }
    }
}

/// A hook decision for each `tools/call` of `search` in `line`, as the host
/// would ask for one before sending it.
fn decide_like_a_host(gw: &Gateway, line: &str) {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return;
    };
    let members = match message {
        Value::Array(batch) => batch,
        one => vec![one],
    };
    for m in members {
        if m["method"] == "tools/call" && m["params"]["name"] == "search" {
            let arguments = m["params"].get("arguments").cloned().unwrap_or(json!({}));
            if arguments.is_object() {
                gw.hook("claude-code", "fixtures", "search", &arguments);
            }
        }
    }
}

/// A proxy session driven a line at a time.
struct Live {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Live {
    fn start(gw: &Gateway, mode: &str) -> Self {
        let mut child = gw
            .proxy(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in out.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    /// Send `line` and wait for the answer to `id`.
    fn ask(&mut self, line: &str, id: u64) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        loop {
            let got = self
                .lines
                .recv_timeout(Duration::from_secs(20))
                .expect("an answer");
            if let Ok(message) = serde_json::from_str::<Value>(&got)
                && message["id"] == id
            {
                return message;
            }
        }
    }

    fn end(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}
