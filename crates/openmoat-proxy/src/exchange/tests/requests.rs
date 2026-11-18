//! A host's request rules inside a terminated tunnel (ADR-062 step 0): a
//! denied request is answered by the proxy and never reaches the upstream,
//! even when a secret's `allow` rule names it; any other request passes.

use super::*;
use openmoat_core::rule_id::REQUEST_RULE;

fn with_rules(deny: &[&str]) -> Setup {
    let mut s = setup();
    s.requests = Requests::default().deny(HOST, deny).unwrap();
    s
}

fn post(path: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\
         Content-Length: 2\r\n\r\n{{}}"
    )
}

#[test]
fn a_deny_rule_wins_over_a_secrets_allow_and_nothing_is_sent() {
    // The secret's `allow` names `POST /repos/*/*/issues`.
    let s = with_rules(&["POST /repos/*/*/issues"]);
    for path in [
        "/repos/o/r/issues",
        "/REPOS/o/r/issues",
        "/repos/o/r/issues?x=1",
    ] {
        let out = exchange(&s, &post(path), OK);
        assert!(out.agent.starts_with("HTTP/1.1 403 "), "{}", out.agent);
        assert!(out.agent.contains(REQUEST_RULE), "{}", out.agent);
        assert_eq!(out.connects, 0, "no connection to the upstream");
        assert!(out.upstream.is_empty(), "{}", out.upstream);
        assert_eq!(out.rules(), [REQUEST_RULE], "{:?}", out.rows);
        assert!(
            !format!("{:?}", out.rows).contains("/repos/o"),
            "{:?}",
            out.rows
        );
        out.kept_secret();
    }
}

#[test]
fn a_request_no_deny_rule_names_passes_and_says_it_was_checked() {
    let s = with_rules(&["POST /gists"]);
    let out = exchange(&s, &post("/repos/o/r/issues"), OK);
    assert!(out.agent.starts_with("HTTP/1.1 200 OK"), "{}", out.agent);
    assert!(
        out.upstream.starts_with("POST /repos/o/r/issues "),
        "{}",
        out.upstream
    );
    let reasons = &out.rows[0].1.reasons;
    assert!(
        reasons.iter().any(|r| r.contains("no request rule")),
        "{reasons:?}"
    );
    out.kept_secret();
}

/// After a secret read (ADR-062 §3) a `requests:` host takes reads only:
/// a `GET` without a body passes, a write or a read with a body is refused
/// with `session-taint` and never reaches the upstream.
#[test]
fn a_tainted_session_only_reads_from_a_host_with_request_rules() {
    let mut s = with_rules(&["POST /gists"]);
    s.reads_only = true;
    let out = exchange(&s, &get("/repos/o/r", ""), OK);
    assert!(out.agent.starts_with("HTTP/1.1 200 OK"), "{}", out.agent);
    let body_get = get("/repos/o/r", "Content-Length: 2\r\n") + "{}";
    let long_get = get(&format!("/repos/o/r?q={}", "a".repeat(2100)), "");
    for request in [post("/repos/o/r/issues"), body_get, long_get] {
        let out = exchange(&s, &request, OK);
        assert!(out.agent.starts_with("HTTP/1.1 403 "), "{}", out.agent);
        assert_eq!(out.rules(), [openmoat_core::rule_id::SESSION_TAINT]);
        assert_eq!(out.connects, 0, "no connection to the upstream");
        out.kept_secret();
    }
}
