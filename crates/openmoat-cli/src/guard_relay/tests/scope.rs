//! Whose calls the service decides (ADR-069): the run's agent, in the run's
//! own sessions. Every process in the sandbox holds the token, so a script
//! could otherwise send calls under any host and any session.

use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::Host;
use serde_json::json;

use super::super::service::{MAX_SESSIONS, RULE_HOST, RULE_SESSION};
use super::{RUN, ask, request, service, service_for, token};
use crate::home::Home;

/// A Claude Code `event` payload in `session`.
fn payload(event: &str, session: &str) -> String {
    let mut body = json!({
        "session_id": session,
        "transcript_path": "/t.jsonl",
        "cwd": "/p",
        "hook_event_name": event,
    });
    if event == "PreToolUse" {
        body["tool_name"] = json!("mcp__notes__save");
        body["tool_input"] = json!({"text": "hello"});
        body["tool_use_id"] = json!("toolu_1");
    } else {
        body["source"] = json!("resume");
    }
    body.to_string()
}

/// A call of `host`'s hook with `payload`, as the agent's guard sends it.
fn call(host: Host, payload: &str) -> super::Request {
    let mut sent = request(token(), payload);
    host.id().clone_into(&mut sent.host);
    sent.continue_cli = false;
    sent
}

/// Whether the service decided `sent` (started the guard), or refused it.
fn decided(service: &super::Service, sent: &super::Request) -> bool {
    let reply = ask(service, sent).unwrap();
    let out = String::from_utf8_lossy(&reply.stdout).into_owned();
    if out.contains("args=guard") {
        return true;
    }
    assert_eq!(reply.code, 2, "a refusal is a deny");
    assert!(reply.stdout.is_empty(), "{out}");
    false
}

/// The rules of the run session's rows.
fn run_rules(home: &Home) -> Vec<String> {
    let rows = home.open_audit().unwrap().session(RUN).unwrap();
    rows.into_iter().flat_map(|r| r.rules).collect()
}

/// A row an earlier hook outside the run left for `host` in `session`.
fn seen_outside(home: &Home, host: Host, session: &str) {
    let store = Store::open_existing(&home.audit_path()).unwrap();
    let decision = Decision::single(Verdict::Allow, "dev-shell", "outside");
    store
        .record(&NewEvent {
            host: host.id(),
            session_id: session,
            call_id: None,
            cwd: None,
            tool: "Bash",
            action: None,
            decision: &decision,
            latency_us: 0,
        })
        .unwrap();
}

#[test]
fn a_call_for_another_host_is_refused_with_a_row() {
    let (_dir, home, service) = service(0);
    let mcp = payload("PreToolUse", "fresh");
    assert!(!decided(&service, &call(Host::Codex, &mcp)));
    assert!(decided(&service, &call(Host::ClaudeCode, &mcp)));
    assert_eq!(run_rules(&home), [RULE_HOST]);
    // Nothing the guard records came from the refused call.
    let fresh = home.open_audit().unwrap().session("fresh").unwrap();
    assert_eq!(fresh.len(), 0, "{fresh:?}");
}

#[test]
fn a_program_openmoat_does_not_know_is_bound_to_its_first_host() {
    let (_dir, home, service) = service_for(0, None);
    assert!(decided(
        &service,
        &call(Host::Codex, &payload("SessionStart", "a"))
    ));
    assert!(!decided(
        &service,
        &call(Host::ClaudeCode, &payload("PreToolUse", "b"))
    ));
    assert_eq!(run_rules(&home), [RULE_HOST]);
}

#[test]
fn only_the_runs_own_sessions_are_decided() {
    let (_dir, home, service) = service(0);
    seen_outside(&home, Host::ClaudeCode, "outside");
    seen_outside(&home, Host::Codex, "codex-outside");
    let pre = |s: &str| call(Host::ClaudeCode, &payload("PreToolUse", s));
    let start = |s: &str| call(Host::ClaudeCode, &payload("SessionStart", s));
    // A session the log has never seen joins on any call.
    assert!(decided(&service, &pre("new")));
    assert!(decided(&service, &pre("new")));
    // One that ran outside the run: not by a tool call, only by the agent's
    // own session start (a resume); then its calls are decided.
    assert!(!decided(&service, &pre("outside")));
    assert!(decided(&service, &start("outside")));
    assert!(decided(&service, &pre("outside")));
    // Another agent's session is not resumed by this one's session start.
    assert!(!decided(&service, &start("codex-outside")));
    // The run's own session, and any other run's.
    assert!(!decided(&service, &pre(RUN)));
    assert!(!decided(&service, &start("run-2-feedbeef")));
    assert_eq!(run_rules(&home), [RULE_SESSION; 4]);
}

#[test]
fn a_run_takes_a_bounded_number_of_sessions() {
    let (_dir, home, service) = service(0);
    for n in 0..MAX_SESSIONS {
        let sent = call(Host::ClaudeCode, &payload("PreToolUse", &format!("s{n}")));
        assert!(decided(&service, &sent), "session {n}");
    }
    let over = call(Host::ClaudeCode, &payload("PreToolUse", "one-more"));
    assert!(!decided(&service, &over));
    // The sessions it took stay decided.
    assert!(decided(
        &service,
        &call(Host::ClaudeCode, &payload("PreToolUse", "s0"))
    ));
    assert_eq!(run_rules(&home), [RULE_SESSION]);
}
