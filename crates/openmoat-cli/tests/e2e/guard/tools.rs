//! The hook on web and MCP tools: a `WebFetch` of an unlisted host, a
//! `Monitor` WebSocket, and MCP arguments checked as paths.

use crate::common::{Sandbox, hook_output as decision, stderr, stdout};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

#[test]
fn webfetch_to_an_unlisted_host_defers_but_a_websocket_is_denied() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    sb.moat(&["init", "--yes"]);
    for (name, code, verdict, rule) in [
        ("webfetch-docs", 0, "defer", ""),
        ("webfetch", 0, "allow", "registries"),
        ("monitor-ws", 2, "deny", "default.net"),
    ] {
        let out = sb.guard_fixture(Host::ClaudeCode, &format!("{name}.json"));
        assert_eq!(out.status.code(), Some(code), "{name}: {}", stderr(&out));
        let d = decision(&out);
        assert_eq!(d["permissionDecision"], verdict, "{name}");
        let reason = d["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains(rule), "{name}: {reason}");
    }
    let shown = sb.moat(&["show", "--recent", "3"]);
    assert!(
        stdout(&shown).contains("fetch https://docs.rs/serde/latest/serde/"),
        "{}",
        stdout(&shown)
    );
}

#[test]
fn mcp_arguments_are_checked_as_paths() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    sb.moat(&["init", "--yes"]);
    let out = sb.guard_fixture(Host::ClaudeCode, "mcp_filesystem_read_secret.json");
    assert_eq!(out.status.code(), Some(2));
    let d = decision(&out);
    assert_eq!(d["permissionDecision"], "deny");
    let reason = d["permissionDecisionReason"].to_string();
    assert!(reason.contains("secrets-paths"), "{reason}");

    // Searched at 8 levels of nesting, the path is denied; one level deeper it is
    // not searched, and the call is left to the agent instead of being allowed.
    for (levels, verdict, why) in [(8, "deny", "secrets-paths"), (9, "defer", "")] {
        let (open, close) = (r#"{"o":"#.repeat(levels), "}".repeat(levels));
        let input = format!(r#"{open}{{"path":"~/.ssh/id_rsa"}}{close}"#);
        let payload =
            format!(r#"{{"tool_name":"mcp__filesystem__read_file","tool_input":{input}}}"#);
        let d = decision(&sb.guard(Host::ClaudeCode.id(), &payload));
        assert_eq!(d["permissionDecision"], verdict, "{levels}");
        let reason = d["permissionDecisionReason"].to_string();
        assert!(reason.contains(why), "{reason}");
    }
}
