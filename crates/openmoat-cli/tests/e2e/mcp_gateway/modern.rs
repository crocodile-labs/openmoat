//! MCP 2026-07-28 through the real binary (ADR-114): a server's
//! `server/discover` answer and the identity its results give are held until
//! a person accepts them, a server that later names itself as another has its
//! calls refused, and a 2026-07-28 result asking for a URL-mode elicitation
//! to the cloud metadata address or for sampling never reaches the host.

use serde_json::{Value, json};

use super::{Gateway, answer};
use crate::common::{OK, text};
use openmoat_hosts::Host;

fn meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}}})
}

fn discover(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "server/discover", "params": {"_meta": meta()}})
        .to_string()
}

fn list(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {"_meta": meta()}})
        .to_string()
}

fn call(id: u64, arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "search", "arguments": arguments, "_meta": meta()}})
    .to_string()
}

#[test]
fn a_2026_server_is_held_until_accepted_and_another_identity_stops_its_calls() {
    let gw = Gateway::new();
    let first = gw.session("modern", &[discover(1), list(2)]);
    let discovered = answer(&first, 1);
    assert!(
        discovered["result"].get("instructions").is_none(),
        "{first}"
    );
    let accepted = gw.sb.moat_approving(&["mcp", "accept", "docs"]);
    assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
    assert!(
        text(&accepted).contains("server/discover"),
        "{}",
        text(&accepted)
    );

    let again = gw.session("modern", &[discover(1)]);
    assert_eq!(
        answer(&again, 1)["result"]["instructions"],
        "Search the docs."
    );

    let arguments = json!({"q": "rust"});
    for session in ["m1", "m2"] {
        assert_ne!(
            gw.hook(Host::ClaudeCode.id(), session, "search", &arguments),
            "deny"
        );
    }
    let swapped = gw.session("imposter", &[call(1, &arguments)]);
    let named = &answer(&swapped, 1)["result"]["_meta"]["io.modelcontextprotocol/serverInfo"];
    assert_eq!(named["name"], "recording", "{swapped}");
    gw.forget();
    let refused = gw.session("modern", &[call(2, &arguments)]);
    let why = answer(&refused, 2).to_string();
    assert!(why.contains("server information"), "{why}");
    assert!(gw.calls().is_empty(), "{}", gw.recorded());
}

#[test]
fn an_input_required_result_with_a_metadata_url_or_sampling_never_reaches_the_host() {
    let gw = Gateway::new();
    let arguments = json!({"q": "login"});
    assert_ne!(
        gw.hook(Host::ClaudeCode.id(), "r1", "search", &arguments),
        "deny"
    );
    let host = gw.session("mrtr", &[call(1, &arguments)]);
    let got = answer(&host, 1);
    assert_eq!(got["error"]["code"], -32001, "{host}");
    assert!(!host.contains("169.254.169.254/latest"), "{host}");
    assert!(!host.contains("drop.evil.example"), "{host}");
}
