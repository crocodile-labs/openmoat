use std::net::SocketAddr;

use openmoat_core::{EvalContext, RepoPolicy};

use super::*;
use crate::decide::{address_policy, named_on};

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    }
}

/// `(verdict, first rule)` of `host:port` under `policy`.
fn decide(policy: &Policy, host: &str, port: u16) -> (Verdict, String) {
    let compiled = CompiledPolicy::compile(policy, &ctx()).unwrap();
    let port_policy = port_policy(policy);
    let ports = CompiledPolicy::compile(&port_policy, &ctx()).unwrap();
    let d = host_port(&compiled, &ports, host, port);
    (d.verdict, d.rules[0].clone())
}

const POLICY: &str = "version: 1\ndefaults: { '*': deny, fetch: ask }\n\
    deny:\n  - id: no-ssh\n    net: ['*:22', 'blocked.example.com']\n\
    allow:\n  - id: web\n    net: [example.com, '*.cdn.test', '!evil.cdn.test', 'fe80::1']\n\
    \x20 - id: alt\n    net: ['alt.example.com:8443', '*.svc.test:9000', '!bad.svc.test:9000']\n\
    \x20 - id: everywhere\n    fetch: ['*']\n";

#[test]
fn a_host_rule_without_a_port_allows_443_and_80_only() {
    let policy = Policy::parse(POLICY).unwrap();
    let allow = |rule: &str| (Verdict::Allow, rule.to_owned());
    assert_eq!(decide(&policy, "example.com", 443), allow("web"));
    assert_eq!(decide(&policy, "example.com", 80), allow("web"));
    assert_eq!(decide(&policy, "a.cdn.test", 443), allow("web"));
    for port in [22, 8443, 25, 6379] {
        let (verdict, rule) = decide(&policy, "example.com", port);
        assert_eq!(verdict, Verdict::Deny, "{port}");
        assert!(
            rule == RULE_PORT || (port == 22 && rule == "no-ssh"),
            "{port}: {rule}"
        );
    }
    // A `fetch: ['*']` allow opens every host, on 443 and 80 only.
    assert_eq!(decide(&policy, "any.test", 443), allow("everywhere"));
    assert_eq!(
        decide(&policy, "any.test", 8443),
        (Verdict::Deny, RULE_PORT.to_owned())
    );
    // IPv6 literals take no port.
    assert_eq!(decide(&policy, "fe80::1", 443).0, Verdict::Allow);
    assert_eq!(
        decide(&policy, "fe80::1", 8443),
        (Verdict::Deny, RULE_PORT.to_owned())
    );
}

#[test]
fn a_host_port_rule_allows_that_port_and_no_other() {
    let policy = Policy::parse(POLICY).unwrap();
    assert_eq!(
        decide(&policy, "alt.example.com", 8443),
        (Verdict::Allow, "alt".to_owned())
    );
    // 443 comes from `fetch: ['*']`, which names no other port.
    assert_eq!(
        decide(&policy, "alt.example.com", 443),
        (Verdict::Allow, "everywhere".to_owned())
    );
    assert_eq!(decide(&policy, "alt.example.com", 8444).0, Verdict::Deny);
    assert_eq!(decide(&policy, "x.svc.test", 9000).0, Verdict::Allow);
    assert_eq!(decide(&policy, "x.svc.test", 9001).0, Verdict::Deny);
    assert_eq!(decide(&policy, "bad.svc.test", 9000).0, Verdict::Deny);
}

#[test]
fn denies_and_exclusions_hold_on_every_port() {
    let policy = Policy::parse(POLICY).unwrap();
    assert_eq!(
        decide(&policy, "example.com", 22),
        (Verdict::Deny, "no-ssh".to_owned())
    );
    assert_eq!(
        decide(&policy, "blocked.example.com", 443),
        (Verdict::Deny, "no-ssh".to_owned())
    );
    // `!evil.cdn.test` excludes the host on 443 and on any port a rule names.
    let excluded = "version: 1\ndefaults: { '*': deny }\nallow:\n  - id: cdn\n    \
        net: ['*.cdn.test', '*.cdn.test:8443', '!evil.cdn.test']\n";
    let excluded = Policy::parse(excluded).unwrap();
    assert_eq!(decide(&excluded, "ok.cdn.test", 8443).0, Verdict::Allow);
    assert_eq!(decide(&excluded, "evil.cdn.test", 443).0, Verdict::Deny);
    assert_eq!(decide(&excluded, "evil.cdn.test", 8443).0, Verdict::Deny);
    // A deny list with an exclusion keeps it on every port.
    let deny_all_but = "version: 1\ndefaults: { '*': deny }\n\
        deny:\n  - id: only-github\n    net: ['*', '!github.com']\n\
        allow:\n  - id: gh\n    net: [github.com]\n";
    let deny_all_but = Policy::parse(deny_all_but).unwrap();
    assert_eq!(decide(&deny_all_but, "github.com", 443).0, Verdict::Allow);
    assert_eq!(
        decide(&deny_all_but, "github.com", 22),
        (Verdict::Deny, RULE_PORT.to_owned())
    );
    assert_eq!(decide(&deny_all_but, "evil.test", 443).0, Verdict::Deny);
}

#[test]
fn cloud_metadata_is_refused_whatever_a_port_rule_says() {
    let policy = Policy::parse(
        "version: 1\nallow:\n  - id: wide\n    net: ['*:80', 'metadata.google.internal:80']\n",
    )
    .unwrap();
    assert_eq!(
        decide(&policy, "metadata.google.internal", 80),
        (Verdict::Deny, crate::decide::RULE_ADDRESS.to_owned())
    );
}

#[test]
fn a_private_address_named_with_a_port_is_reachable_on_that_port_only() {
    let policy = Policy::parse(
        "version: 1\nallow:\n  - id: db\n    net: ['10.0.0.5:5432', '10.0.1.*', '!10.0.1.9']\n",
    )
    .unwrap();
    let addresses = address_policy(&policy);
    let addresses = CompiledPolicy::compile(&addresses, &ctx()).unwrap();
    let named = |a: &str| named_on(&addresses, a.parse::<SocketAddr>().unwrap());
    assert!(named("10.0.0.5:5432"));
    assert!(!named("10.0.0.5:5433"));
    assert!(named("10.0.1.7:6379"));
    // The exclusion holds on every port.
    assert!(!named("10.0.1.9:443"));
    assert!(!named("10.0.1.9:6379"));
}

/// `openmoat run`'s proxy: a trusted repository policy's deny refuses a host
/// the user allows, and a host only the repository allows stays refused.
#[test]
fn a_repository_deny_holds_at_the_proxy_and_its_allow_does_not() {
    let user = Policy::parse(
        "version: 1\ndefaults: { '*': deny }\nallow:\n  - id: web\n    net: [example.com, a.test]\n",
    )
    .unwrap();
    let repo = RepoPolicy::parse(
        "version: 1\ndeny:\n  - id: no-a\n    net: [a.test]\nallow:\n  - id: more\n    \
         net: [b.test, 'b.test:8443']\n",
    )
    .unwrap();
    let merged = repo.merge_deny(&user).unwrap();
    assert_eq!(
        decide(&merged, "a.test", 443),
        (Verdict::Deny, "repo:no-a".to_owned())
    );
    assert_eq!(decide(&merged, "b.test", 443).0, Verdict::Deny);
    assert_eq!(decide(&merged, "b.test", 8443).0, Verdict::Deny);
    assert_eq!(decide(&merged, "example.com", 443).0, Verdict::Allow);
    // Before the merge, the user's own allow let `a.test` through.
    assert_eq!(decide(&user, "a.test", 443).0, Verdict::Allow);
}
