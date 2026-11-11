use std::time::Duration;

use openmoat_core::{Policy, Verdict};
use zeroize::Zeroizing;

use crate::broker::{Broker, BrokerError, Carried, Channel, Holdback, RULE_SECRET_EXPIRED};

/// Generated stand-ins; no real secret is used anywhere in these tests.
const FIRST: &str = "fake-first-0123456789";
const SECOND: &str = "fake-second-abcdef0123456789";

const HEAD: &[u8] =
    b"GET /x HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer moat-secret:t:placeholder\r\n\r\n";

fn broker() -> Broker {
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: t\n    host: api.example.com\n    header: Authorization\n    \
         plain_http: true\n    source:\n      command: { run: [/usr/bin/fake], lifetime: 15m }\n",
    )
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(FIRST.to_owned())))
        .collect();
    Broker::new(secrets).unwrap()
}

fn injected(b: &Broker) -> Option<String> {
    b.inject("api.example.com", Channel::Plain(80), HEAD)
        .map(|head| String::from_utf8(head.to_vec()).unwrap())
}

#[test]
fn a_renewed_value_replaces_the_old_one_in_requests() {
    let b = broker();
    let rotation = b.rotation("t").unwrap();
    assert!(b.rotation("other").is_none());
    // Read once and never renewed: no deadline.
    assert_eq!(rotation.remaining(), None);
    assert!(injected(&b).unwrap().contains(FIRST));
    rotation
        .renew(Zeroizing::new(SECOND.to_owned()), Duration::from_secs(60))
        .unwrap();
    let remaining = rotation.remaining().unwrap();
    assert!(remaining > Duration::from_secs(50) && remaining <= Duration::from_secs(60));
    let head = injected(&b).unwrap();
    assert!(head.contains(SECOND) && !head.contains(FIRST), "{head}");
    assert_eq!(
        b.admit("api.example.com", Channel::Plain(80), HEAD),
        Ok(Vec::new())
    );
    // Debug names the secret only.
    assert_eq!(format!("{rotation:?}"), "Rotation { id: \"t\", .. }");
}

#[test]
fn an_expired_value_is_never_sent_and_the_request_is_refused() {
    let b = broker();
    let rotation = b.rotation("t").unwrap();
    rotation
        .renew(Zeroizing::new(SECOND.to_owned()), Duration::ZERO)
        .unwrap();
    assert_eq!(rotation.remaining(), Some(Duration::ZERO));
    let refused = b
        .admit("api.example.com", Channel::Plain(80), HEAD)
        .unwrap_err();
    assert_eq!(refused.verdict, Verdict::Deny);
    assert_eq!(refused.rules, [RULE_SECRET_EXPIRED]);
    let why = refused.reasons.join(" ");
    assert!(
        why.contains("secret `t`") && why.contains("expired"),
        "{why}"
    );
    assert!(!why.contains(FIRST) && !why.contains(SECOND), "{why}");
    // Should a request get past the check as the value expires, it keeps the
    // placeholder: neither the stale value nor the old one goes in.
    assert_eq!(injected(&b), None);
    // Renewed, it goes in again.
    rotation
        .renew(Zeroizing::new(SECOND.to_owned()), Duration::from_secs(60))
        .unwrap();
    assert!(injected(&b).unwrap().contains(SECOND));
}

#[test]
fn a_value_the_broker_cannot_use_leaves_the_slot_as_it_was() {
    let b = broker();
    let rotation = b.rotation("t").unwrap();
    for bad in ["", "a\r\nX-Evil: 1"] {
        let err = rotation
            .renew(Zeroizing::new(bad.to_owned()), Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(
            err,
            BrokerError::Empty(_) | BrokerError::Control(_)
        ));
    }
    assert_eq!(rotation.remaining(), None);
    assert!(injected(&b).unwrap().contains(FIRST));
}

#[test]
fn a_replaced_value_is_still_caught_leaving_or_coming_back() {
    let b = broker();
    b.rotation("t")
        .unwrap()
        .renew(Zeroizing::new(SECOND.to_owned()), Duration::from_secs(60))
        .unwrap();
    for value in [FIRST, SECOND] {
        let leak = b.leak("evil.example", value.as_bytes()).unwrap();
        assert_eq!((leak.id, leak.carried), ("t", Carried::Value));
        assert_eq!(b.value_in(format!("echo {value}").as_bytes()), Some("t"));
    }
    // The stream keeps back one byte less than the longest value it knows.
    let mut hold = Holdback::new(&b);
    let released = hold.push(&[b'x'; 40]).unwrap();
    assert_eq!(released.len(), 40 - (SECOND.len() - 1));
    let (head, tail) = SECOND.split_at(10);
    let mut hold = Holdback::new(&b);
    assert!(hold.push(head.as_bytes()).is_ok());
    assert_eq!(hold.push(tail.as_bytes()), Err("t"));
}
