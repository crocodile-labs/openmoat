use openmoat_core::{EvalContext, Policy};

use super::*;

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

fn verdicts(yaml: &str, cases: &[(&str, Verdict, &str)]) {
    let policy = Policy::parse(yaml).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    for (h, verdict, rule) in cases {
        let d = host(&compiled, h);
        assert_eq!(
            (d.verdict, d.rules[0].as_str()),
            (*verdict, *rule),
            "{h}: {d:?}"
        );
    }
}

#[test]
fn the_default_policy_allows_only_listed_hosts() {
    verdicts(
        openmoat_core::DEFAULT_POLICY,
        &[
            ("api.github.com", Verdict::Allow, "registries"),
            ("crates.io", Verdict::Allow, "registries"),
            // unlisted: the fetch default (ask) is refused, never asked
            ("evil.example", Verdict::Deny, "default.fetch"),
            // local-net is an ask group: refused too
            ("localhost", Verdict::Deny, "local-net"),
            ("169.254.169.254", Verdict::Deny, "cloud-metadata"),
            ("metadata.google.internal", Verdict::Deny, RULE_ADDRESS),
        ],
    );
}

#[test]
fn net_and_fetch_lists_both_allow_and_deny_wins() {
    let yaml = r#"
version: 1
defaults: { "*": deny }
deny:
  - { id: no-evil, net: ["*.evil.example"] }
allow:
  - { id: docs, fetch: ["docs.rs"] }
  - { id: wide, net: ["*.example", "*.evil.example"] }
"#;
    verdicts(
        yaml,
        &[
            ("docs.rs", Verdict::Allow, "docs"),
            ("a.example", Verdict::Allow, "wide"),
            ("x.evil.example", Verdict::Deny, "no-evil"),
            ("other.org", Verdict::Deny, "default"),
        ],
    );
}

#[test]
fn metadata_names_are_refused_even_when_allowed() {
    let yaml = r#"
version: 1
allow:
  - { id: all, net: ["*"] }
"#;
    verdicts(
        yaml,
        &[
            ("metadata.google.internal", Verdict::Deny, RULE_ADDRESS),
            ("x.metadata.goog", Verdict::Deny, RULE_ADDRESS),
            ("notmetadata.goog", Verdict::Allow, "all"),
        ],
    );
}

#[test]
fn local_and_metadata_addresses_are_forbidden() {
    for (ip, why) in [
        ("127.0.0.1", Forbidden::Loopback),
        ("127.8.9.10", Forbidden::Loopback),
        ("::1", Forbidden::Loopback),
        ("::ffff:127.0.0.1", Forbidden::Loopback),
        ("169.254.169.254", Forbidden::LinkLocal),
        ("::ffff:169.254.169.254", Forbidden::LinkLocal),
        ("64:ff9b::a9fe:a9fe", Forbidden::LinkLocal),
        ("::a9fe:a9fe", Forbidden::LinkLocal),
        ("fe80::1", Forbidden::LinkLocal),
        ("febf::1", Forbidden::LinkLocal),
        ("fd00:ec2::254", Forbidden::Metadata),
        ("100.100.100.200", Forbidden::Metadata),
        ("168.63.129.16", Forbidden::Metadata),
        ("64:ff9b:1::a9fe:a9fe", Forbidden::LinkLocal),
        ("64:ff9b:1::7f00:1", Forbidden::Loopback),
        ("0.0.0.0", Forbidden::NotUnicast),
        ("0.1.2.3", Forbidden::NotUnicast),
        ("::", Forbidden::NotUnicast),
        ("255.255.255.255", Forbidden::NotUnicast),
        ("224.0.0.1", Forbidden::NotUnicast),
        ("ff02::1", Forbidden::NotUnicast),
    ] {
        assert_eq!(forbidden(ip.parse().unwrap()), Some(why), "{ip}");
    }
}

#[test]
fn ordinary_addresses_are_not_forbidden() {
    for ip in [
        "93.184.215.14",
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "2606:4700::1111",
        "fec0::1",
        "fe00::1",
        "::ffff:8.8.8.8",
    ] {
        assert_eq!(forbidden(ip.parse().unwrap()), None, "{ip}");
    }
}

#[test]
fn private_ranges_are_forbidden_in_every_spelling() {
    let private = |range| Some(Forbidden::Private(range));
    let ten = "a private address (10.0.0.0/8)";
    let cgnat = "a shared CGNAT address (100.64.0.0/10)";
    for (ip, why) in [
        ("10.0.0.0", private(ten)),
        ("10.255.255.255", private(ten)),
        ("::ffff:10.0.0.5", private(ten)),
        ("::a00:5", private(ten)),
        ("64:ff9b::a00:5", private(ten)),
        ("172.16.0.0", private("a private address (172.16.0.0/12)")),
        (
            "172.31.255.255",
            private("a private address (172.16.0.0/12)"),
        ),
        ("192.168.0.0", private("a private address (192.168.0.0/16)")),
        (
            "::ffff:192.168.255.255",
            private("a private address (192.168.0.0/16)"),
        ),
        ("100.64.0.0", private(cgnat)),
        ("100.127.255.255", private(cgnat)),
        ("64:ff9b::6440:1", private(cgnat)),
        (
            "198.18.0.0",
            private("a benchmarking address (198.18.0.0/15)"),
        ),
        (
            "198.19.255.255",
            private("a benchmarking address (198.18.0.0/15)"),
        ),
        ("fc00::", private("a unique local address (fc00::/7)")),
        ("fdff:ffff::1", private("a unique local address (fc00::/7)")),
        (
            "192.0.0.170",
            private("an IETF protocol address (192.0.0.0/24)"),
        ),
        ("64:ff9b:1::a00:5", private(ten)),
        // a local-use NAT64 address in a layout other than /96, public inside
        (
            "64:ff9b:1:5db8:d7:e00:808:808",
            private("a local-use NAT64 address (64:ff9b:1::/48)"),
        ),
        // metadata inside a private range stays metadata: never opened
        ("100.100.100.200", Some(Forbidden::Metadata)),
        ("fd00:ec2::254", Some(Forbidden::Metadata)),
    ] {
        assert_eq!(forbidden(ip.parse().unwrap()), why, "{ip}");
    }
}

#[test]
fn only_allow_rules_naming_an_address_open_a_private_one() {
    let yaml = r#"
version: 1
deny:
  - { id: no-lab, net: ["10.9.*"] }
allow:
  - { id: wide, net: ["*", "*.example", "?0.0.0.1"] }
  - { id: lan, net: ["10.0.0.5", "192.168.1.*", "10.9.0.1", "fd12::*"] }
  - { id: docs, fetch: ["172.16.0.9"] }
ask:
  - { id: lab, net: ["100.64.0.1"] }
"#;
    let policy = Policy::parse(yaml).unwrap();
    let named_policy = address_policy(&policy);
    let addresses = CompiledPolicy::compile(&named_policy, &ctx()).unwrap();
    for (ip, open) in [
        ("10.0.0.5", true),
        ("::ffff:10.0.0.5", true),
        ("192.168.1.77", true),
        ("172.16.0.9", true),
        ("fd12::1", true),
        ("10.0.0.6", false),
        ("192.168.2.1", false),
        ("20.0.0.1", false),
        ("10.9.0.1", false),
        ("100.64.0.1", false),
    ] {
        assert_eq!(named(&addresses, ip.parse().unwrap()), open, "{ip}");
    }
}

#[test]
fn a_name_with_a_port_or_a_leading_digit_does_not_name_an_address() {
    let yaml = r#"
version: 1
allow:
  - { id: names, net: ["db.internal:5432", "1password.com", "10.0.0.5", "fd12::*"] }
"#;
    let named_policy = address_policy(&Policy::parse(yaml).unwrap());
    assert_eq!(
        named_policy.allow[0].patterns(Kind::Net),
        ["10.0.0.5", "fd12::*"]
    );
}

#[test]
fn deny_rules_hold_for_every_resolved_address() {
    // There is no CIDR syntax; a range is a glob on the address text.
    let yaml = r#"
version: 1
deny:
  - { id: no-host, net: ["203.0.113.7"] }
  - { id: no-range, fetch: ["198.51.100.*"] }
  - { id: no-v6, net: ["2001:db8::*"] }
allow:
  - { id: all, net: ["*", "203.0.113.*", "2001:db8::1"] }
"#;
    let policy = Policy::parse(yaml).unwrap();
    let address = address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address, &ctx()).unwrap();
    for (ip, rule) in [
        ("203.0.113.7", Some("no-host")),
        ("::ffff:203.0.113.7", Some("no-host")),
        // NAT64 reaches the IPv4 address it carries
        ("64:ff9b::cb00:7107", Some("no-host")),
        ("198.51.100.200", Some("no-range")),
        // an allow naming the address does not lift the deny
        ("2001:db8::1", Some("no-v6")),
        ("2001:db8::abcd", Some("no-v6")),
        // no deny matches: nothing changes, and allows widen nothing here
        ("203.0.113.8", None),
        ("198.51.101.1", None),
        ("2001:db9::1", None),
        ("93.184.215.14", None),
    ] {
        let got = denied(&addresses, ip.parse().unwrap());
        assert_eq!(
            got.as_ref().map(|d| d.rules[0].as_str()),
            rule,
            "{ip}: {got:?}"
        );
    }
}

#[test]
fn an_address_without_rules_is_neither_named_nor_denied() {
    let policy = Policy::parse("version: 1\ndefaults: { \"*\": deny }\n").unwrap();
    let address = address_policy(&policy);
    let addresses = CompiledPolicy::compile(&address, &ctx()).unwrap();
    for ip in ["10.0.0.5", "93.184.215.14", "2606:4700::1111"] {
        let ip = ip.parse().unwrap();
        assert!(!named(&addresses, ip), "{ip}");
        assert_eq!(denied(&addresses, ip), None, "{ip}");
    }
}
