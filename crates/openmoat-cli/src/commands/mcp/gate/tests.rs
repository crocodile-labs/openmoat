use std::path::PathBuf;

use openmoat_audit::{EventId, NewTicket, Store};
use openmoat_hosts::Host;
use serde_json::json;

use super::{Call, Gateway, Method, names_tool};
use crate::home::Home;

#[test]
fn a_hook_decision_names_the_tool_it_decided_and_no_other() {
    let claude = Host::ClaudeCode;
    assert!(names_tool(claude, "mcp__gh__get_issue", "gh", "get_issue"));
    // Claude Code spells a server's and a tool's name with `_` for what it
    // does not keep.
    assert!(names_tool(
        claude,
        "mcp__my_server__get_issue",
        "my.server",
        "get_issue"
    ));
    assert!(names_tool(claude, "mcp__gh__get_issue", "gh", "get.issue"));
    // Another tool of the server, or the same tool of another server: no.
    assert!(!names_tool(claude, "mcp__gh__delete_issue", "gh", "issue"));
    assert!(!names_tool(
        claude,
        "mcp__gh__get_issue",
        "gh",
        "delete_issue"
    ));
    assert!(!names_tool(claude, "mcp__gh__get_issue", "gl", "get_issue"));
    assert!(!names_tool(claude, "mcp__gh__get_issue", "gh", ""));
    // GitHub Copilot CLI joins them with `-`.
    let copilot = Host::CopilotCli;
    assert!(names_tool(copilot, "gh-get_issue", "gh", "get_issue"));
    assert!(!names_tool(copilot, "gh-get_issue", "gh", "issue"));
    // Hermes Agent shortens a name past 64 characters to a hash: no decision
    // names such a tool, so its calls are refused.
    let long = "x".repeat(60);
    let cut = format!("{}_{}", &format!("mcp__gh__{long}")[..55], "0123abcd");
    assert!(!names_tool(Host::Hermes, &cut, "gh", &long));
}

/// Two decisions with the same arguments: `(host, session)` each.
fn two_decisions(store: &Store, decisions: [(&str, &str); 2]) {
    let arguments = json!({"q": "release notes"});
    let canonical = openmoat_hosts::mcp_call_arguments(Some(&arguments));
    let digest = crate::integrity::sha256_hex(canonical.as_bytes());
    for (n, (host, session)) in decisions.into_iter().enumerate() {
        store
            .add_mcp_ticket(&NewTicket {
                event: EventId(i64::try_from(n).unwrap() + 1),
                host,
                session_id: session,
                call_id: None,
                tool: "mcp__docs__search",
                arguments_sha256: &digest,
                verdict: "allow",
            })
            .unwrap();
    }
}

fn search_call() -> serde_json::Value {
    json!({"q": "release notes"})
}

fn take(gateway: &Gateway, store: &Store) -> Option<(String, String)> {
    let arguments = search_call();
    let call = Call {
        method: Method::Tool,
        name: "search",
        arguments: Some(&arguments),
        request: Some("1"),
    };
    gateway
        .take_ticket(store, &call)
        .unwrap()
        .map(|t| (t.host, t.session_id))
}

fn gateway(host: Option<Host>) -> Gateway {
    Gateway::new(
        Home::at(PathBuf::from("/nonexistent/openmoat")),
        "docs",
        host,
    )
    .unwrap()
}

#[test]
fn a_proxy_for_one_agent_takes_only_that_agents_decision() {
    let store = Store::open_in_memory().unwrap();
    two_decisions(&store, [("claude-code", "c1"), ("codex", "x1")]);
    let codex = gateway(Some(Host::Codex));
    assert_eq!(take(&codex, &store), Some(("codex".into(), "x1".into())));
    assert_eq!(take(&codex, &store), None, "Claude Code's stays");
    let claude = gateway(Some(Host::ClaudeCode));
    assert_eq!(
        take(&claude, &store),
        Some(("claude-code".into(), "c1".into()))
    );
}

#[test]
fn a_proxy_takes_the_decision_of_the_session_it_served_first() {
    let store = Store::open_in_memory().unwrap();
    two_decisions(&store, [("claude-code", "a"), ("claude-code", "b")]);
    let proxy = gateway(Some(Host::ClaudeCode));
    assert_eq!(
        take(&proxy, &store),
        Some(("claude-code".into(), "a".into()))
    );
    // Session b's proxy and session a's both send the same call again: a's
    // takes a's decision, although b's is older.
    two_decisions(&store, [("claude-code", "b"), ("claude-code", "a")]);
    assert_eq!(
        take(&proxy, &store),
        Some(("claude-code".into(), "a".into()))
    );
    // With no decision of its own session left, it takes another (a host
    // that starts a new session on the same server, as `/clear` does).
    assert_eq!(
        take(&proxy, &store),
        Some(("claude-code".into(), "b".into()))
    );
}

#[test]
fn a_proxy_wrapped_before_it_named_its_agent_takes_any_agents_decision() {
    let store = Store::open_in_memory().unwrap();
    two_decisions(&store, [("codex", "x1"), ("claude-code", "c1")]);
    let any = gateway(None);
    assert_eq!(take(&any, &store), Some(("codex".into(), "x1".into())));
}
