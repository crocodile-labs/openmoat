use openmoat_core::{Policy, Verdict};
use zeroize::Zeroizing;

use super::{Broker, BrokerError, Carried, Channel, RULE_SECRET, Watch};

/// A generated stand-in; no real secret is used anywhere in these tests.
const VALUE: &str = "fake-0123456789abcdef";

fn broker(value: &str) -> Result<Broker, BrokerError> {
    broker_with(value, false)
}

fn broker_with(value: &str, plain_http: bool) -> Result<Broker, BrokerError> {
    let policy = Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: {{ env: FAKE_TOKEN }}\n    plain_http: {plain_http}\n",
    ))
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(value.to_owned())))
        .collect();
    Broker::new(secrets)
}

#[test]
fn values_that_could_break_a_header_are_refused() {
    assert!(matches!(broker(""), Err(BrokerError::Empty(id)) if id == "gh"));
    for bad in ["a\r\nX-Evil: 1", "a\nb", "a\0b"] {
        let err = broker(bad).unwrap_err();
        assert!(matches!(err, BrokerError::Control(_)), "{bad:?}");
        assert!(!err.to_string().contains(bad), "{err}");
    }
}

#[test]
fn the_owner_may_receive_both_forms_and_no_other_host_may() {
    let b = broker(VALUE).unwrap();
    let placeholder = b"Authorization: Bearer moat-secret:gh:placeholder";
    let value = format!("POST /x HTTP/1.1\r\n\r\ntoken={VALUE}");
    assert!(b.leak("api.github.com", placeholder).is_none());
    assert!(b.leak("api.github.com", value.as_bytes()).is_none());
    let leak = b.leak("evil.example", placeholder).unwrap();
    assert_eq!(
        (leak.id, leak.owner, leak.carried),
        ("gh", "api.github.com", Carried::Placeholder)
    );
    let leak = b.leak("github.com", value.as_bytes()).unwrap();
    assert_eq!(leak.carried, Carried::Value);
    let decision = leak.decision("github.com");
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(decision.rules, [RULE_SECRET]);
    assert!(!decision.reasons.join(" ").contains(VALUE), "{decision:?}");
    assert!(b.leak("evil.example", b"GET / HTTP/1.1\r\n\r\n").is_none());
}

#[test]
fn a_secret_split_across_chunks_is_found() {
    let b = broker(VALUE).unwrap();
    let stream = format!("{}{VALUE}{}", "x".repeat(5000), "y".repeat(100));
    for cut in 1..VALUE.len() {
        let at = 5000 + cut;
        let mut watch = Watch::new(&b, "evil.example");
        assert!(watch.next(&stream.as_bytes()[..at]).is_none(), "{cut}");
        assert!(watch.next(&stream.as_bytes()[at..]).is_some(), "{cut}");
    }
    let mut owner = Watch::new(&b, "api.github.com");
    assert!(owner.next(stream.as_bytes()).is_none());
}

#[test]
fn nothing_brokered_finds_nothing() {
    let b = Broker::default();
    assert!(
        Watch::new(&b, "evil.example")
            .next(VALUE.as_bytes())
            .is_none()
    );
}

#[test]
fn debug_names_ids_and_hosts_never_values() {
    let shown = format!("{:?}", broker(VALUE).unwrap());
    assert!(
        shown.contains("gh") && shown.contains("api.github.com"),
        "{shown}"
    );
    assert!(!shown.contains(VALUE), "{shown}");
}

#[test]
fn the_owner_head_gets_the_value_in_place_of_the_placeholder() {
    let b = broker_with(VALUE, true).unwrap();
    let head = b"GET /moat-secret:gh:placeholder HTTP/1.1\r\nHost: api.github.com\r\n\
                 authorization: Bearer moat-secret:gh:placeholder\r\n\
                 X-Other: moat-secret:gh:placeholder\r\nConnection: close\r\n\r\n";
    let out = b
        .inject("api.github.com", Channel::Plain(80), head)
        .unwrap();
    assert_eq!(
        String::from_utf8(out.to_vec()).unwrap(),
        format!(
            "GET /moat-secret:gh:placeholder HTTP/1.1\r\nHost: api.github.com\r\n\
             authorization: Bearer {VALUE}\r\nX-Other: moat-secret:gh:placeholder\r\n\
             Connection: close\r\n\r\n"
        )
    );
}

#[test]
fn a_missing_header_is_added_and_other_hosts_get_nothing() {
    let b = broker_with(VALUE, true).unwrap();
    let head = b"GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n";
    let out = b
        .inject("api.github.com", Channel::Plain(80), head)
        .unwrap();
    let added = format!("Connection: close\r\nAuthorization: {VALUE}\r\n\r\n");
    assert!(out.ends_with(added.as_bytes()));
    assert!(b.inject("github.com", Channel::Plain(80), head).is_none());
    assert!(
        Broker::default()
            .inject("api.github.com", Channel::Plain(80), head)
            .is_none()
    );
    assert!(b.withheld("api.github.com", 80).is_empty());
}

#[test]
fn without_plain_http_the_owner_head_is_left_alone() {
    let b = broker(VALUE).unwrap();
    let head = b"GET / HTTP/1.1\r\nAuthorization: moat-secret:gh:placeholder\r\n\r\n";
    assert!(
        b.inject("api.github.com", Channel::Plain(80), head)
            .is_none()
    );
    assert_eq!(
        b.withheld("api.github.com", 80),
        ["secret `gh` not injected: plain HTTP needs `plain_http: true`"]
    );
    assert!(b.withheld("github.com", 80).is_empty());
}

#[test]
fn a_request_the_server_echoes_back_gets_no_value() {
    // A TRACE answer (and IIS's TRACK) is the request as the server got it,
    // so a value put in would come back to the agent.
    let b = broker_with(VALUE, true).unwrap();
    for method in ["TRACE", "TRACK", "trace"] {
        let head = format!(
            "{method} / HTTP/1.1\r\nHost: api.github.com\r\n\
             Authorization: moat-secret:gh:placeholder\r\n\r\n"
        );
        assert!(
            b.inject("api.github.com", Channel::Plain(80), head.as_bytes())
                .is_none(),
            "{method}"
        );
    }
    let head = b"TRACEX / HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    assert!(
        b.inject("api.github.com", Channel::Plain(80), head)
            .is_some()
    );
}

#[test]
fn a_secret_header_without_the_placeholder_is_replaced_by_the_secret() {
    let b = broker_with(VALUE, true).unwrap();
    let head = b"GET / HTTP/1.1\r\nAuthorization: Bearer chosen-by-client\r\n\
                 authorization: Bearer moat-secret:gh:placeholder\r\nX-Other: 1\r\n\r\n";
    let out = String::from_utf8(
        b.inject("api.github.com", Channel::Plain(80), head)
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        out,
        format!("GET / HTTP/1.1\r\nauthorization: Bearer {VALUE}\r\nX-Other: 1\r\n\r\n")
    );
    let head = b"GET / HTTP/1.1\r\nAUTHORIZATION: chosen-by-client\r\n\r\n";
    let out = String::from_utf8(
        b.inject("api.github.com", Channel::Plain(80), head)
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        out,
        format!("GET / HTTP/1.1\r\nAuthorization: {VALUE}\r\n\r\n")
    );
}

/// Plain-HTTP injection is bound to a port: 80, or the one the secret names.
/// Another port of the owner host keeps the placeholder; it is not refused.
#[test]
fn only_the_secrets_port_gets_the_value() {
    let head = b"GET / HTTP/1.1\r\nAuthorization: moat-secret:gh:placeholder\r\n\r\n";
    let default = broker_with(VALUE, true).unwrap();
    assert!(
        default
            .inject("api.github.com", Channel::Plain(80), head)
            .is_some()
    );
    assert!(
        default
            .inject("api.github.com", Channel::Plain(8080), head)
            .is_none()
    );
    assert_eq!(
        default.withheld("api.github.com", 8080),
        ["secret `gh` not injected: it goes to port 80 only, not 8080"]
    );
    assert!(default.leak("api.github.com", head).is_none());
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: { env: FAKE_TOKEN }\n    plain_http: true\n    port: 8080\n",
    )
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(VALUE.to_owned())))
        .collect();
    let named = Broker::new(secrets).unwrap();
    let out = named
        .inject("api.github.com", Channel::Plain(8080), head)
        .unwrap();
    assert!(String::from_utf8_lossy(&out).contains(VALUE));
    assert!(
        named
            .inject("api.github.com", Channel::Plain(80), head)
            .is_none()
    );
    assert!(named.withheld("api.github.com", 8080).is_empty());
}

fn routed(extra: &str) -> Broker {
    let policy = Policy::parse(&format!(
        "version: 1\nsecrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: {{ env: FAKE_TOKEN }}\n{extra}    allow:\n      - GET /repos/**\n      \
         - POST /repos/*/*/issues\n",
    ))
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(VALUE.to_owned())))
        .collect();
    Broker::new(secrets).unwrap()
}

#[test]
fn a_request_the_rules_do_not_name_is_refused_before_the_value_goes_in() {
    use super::RULE_SECRET_ROUTE;
    let plain = routed("    plain_http: true\n");
    let tls = routed("    tls: terminate\n");
    let head = |line: &str, extra: &str| format!("{line}\r\nHost: api.github.com\r\n{extra}\r\n");
    for (b, channel) in [(&plain, Channel::Plain(80)), (&tls, Channel::Terminated)] {
        let ok = b
            .admit(
                "api.github.com",
                channel,
                head("GET /repos/o/r HTTP/1.1", "").as_bytes(),
            )
            .unwrap();
        assert_eq!(
            ok,
            ["secret `gh` goes in: the request matches `GET /repos/**`"]
        );
        for (line, extra, why) in [
            ("DELETE /repos/o/r HTTP/1.1", "", "matches none"),
            ("GET /user/keys HTTP/1.1", "", "matches none"),
            ("GET /repos/../user/keys HTTP/1.1", "", "`..`"),
            ("GET /repos/%2e%2e/user HTTP/1.1", "", "`..`"),
            ("GET /repos/x%2f..%2fuser HTTP/1.1", "", "decodes to `/`"),
            (
                "POST /repos/o/r/issues HTTP/1.1",
                "X-HTTP-Method-Override: DELETE\r\n",
                "another method",
            ),
            (
                "POST /repos/o/r/issues?_method=DELETE HTTP/1.1",
                "",
                "`_method`",
            ),
        ] {
            let refused = b
                .admit("api.github.com", channel, head(line, extra).as_bytes())
                .unwrap_err();
            assert_eq!(refused.verdict, Verdict::Deny);
            assert_eq!(refused.rules, [RULE_SECRET_ROUTE]);
            assert!(refused.reasons[0].contains(why), "{line}: {refused:?}");
            assert!(!refused.reasons[0].contains("user"), "no path: {refused:?}");
        }
    }
    // Another channel, another host: the secret does not go in, so no rule applies.
    let other = head("DELETE /x HTTP/1.1", "");
    assert!(
        plain
            .admit("api.github.com", Channel::Plain(8080), other.as_bytes())
            .unwrap()
            .is_empty()
    );
    assert!(
        plain
            .admit("api.github.com", Channel::Terminated, other.as_bytes())
            .unwrap()
            .is_empty()
    );
    assert!(
        tls.admit("api.github.com", Channel::Plain(80), other.as_bytes())
            .unwrap()
            .is_empty()
    );
    assert!(
        tls.admit("github.com", Channel::Terminated, other.as_bytes())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_terminated_secret_goes_into_tunnel_requests_only() {
    let tls = routed("    tls: terminate\n");
    let head = b"GET /repos/o HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    let out = tls
        .inject("api.github.com", Channel::Terminated, head)
        .unwrap();
    assert!(String::from_utf8_lossy(&out).contains(&format!("Authorization: {VALUE}\r\n")));
    assert!(
        tls.inject("api.github.com", Channel::Plain(80), head)
            .is_none()
    );
    assert!(
        tls.inject("github.com", Channel::Terminated, head)
            .is_none()
    );
}
