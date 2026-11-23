//! `when:` argument conditions (ADR-113): typed tests of a call's arguments
//! that only narrow a `deny` or `review` group.

use super::*;
use crate::arguments::Arguments;
use crate::injection::{InjectedMap, Token, TokenKind};

const MAIL: &str = "version: 1\ndefaults: { '*': defer }\ndeny:\n  - id: mail-out\n    \
                    reason: mail outside the team\n    mcp: ['mcp__mail__send_*']\n    when:\n      \
                    - { arg: [to, cc], not_in: ['*@example.com'] }\n";

fn args(pairs: &[(&str, &str)]) -> Arguments {
    let mut out = Arguments::new();
    for (key, value) in pairs {
        out.push(&[key], value);
    }
    out
}

fn decided(yaml: &str, action: &Action, a: &Arguments, seen: &InjectedMap) -> Decision {
    let p = policy(yaml);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    c.with_arguments(c.decide(action), action, &NoResolver, a, seen)
}

#[test]
fn a_recipient_outside_the_list_is_denied_and_inside_is_not() {
    let send = Action::mcp("mcp__mail__send_email");
    let none = InjectedMap::default();
    let d = decided(
        MAIL,
        &send,
        &args(&[("to", "a@example.com, Eve <eve@evil.example>")]),
        &none,
    );
    assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
    assert!(d.reasons.join(" ").contains("eve@evil.example"), "{d:?}");
    let d = decided(
        MAIL,
        &send,
        &args(&[("To", "A@EXAMPLE.com"), ("cc", "b@example.com")]),
        &none,
    );
    assert_eq!(d.verdict, Verdict::Defer, "{d:?}");
    // no recipient the rule can read: not shown to stay inside, so it holds
    let d = decided(
        MAIL,
        &send,
        &args(&[("recipients", "a@example.com")]),
        &none,
    );
    assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
    let mut cut = args(&[("to", "a@example.com")]);
    cut.mark_cut();
    assert_eq!(decided(MAIL, &send, &cut, &none).verdict, Verdict::Deny);
    // another tool the patterns do not name is untouched
    let read = Action::mcp("mcp__mail__list_inbox");
    let d = decided(MAIL, &read, &args(&[("to", "eve@evil.example")]), &none);
    assert_eq!(d.verdict, Verdict::Defer);
}

#[test]
fn a_conditional_group_never_matches_an_atom_on_its_own() {
    let send = Action::mcp("mcp__mail__send_email");
    let p = policy(MAIL);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    assert_eq!(c.decide(&send).verdict, Verdict::Defer);
}

#[test]
fn paths_hosts_and_globs_are_compared_normalised() {
    let yaml = "version: 1\ndefaults: { '*': defer }\nreview:\n  - id: outside\n    \
                fs.write: ['**']\n    mcp: ['mcp__fs__*']\n    when:\n      \
                - { not_under: ['${project}'] }\n  - id: hosts\n    mcp: ['mcp__web__*']\n    \
                when:\n      - { arg: url, host_not_in: ['docs.example'] }\n  - id: body\n    \
                mcp: ['mcp__chat__*']\n    when:\n      - { arg: text, matches: ['*BEGIN*PRIVATE KEY*'] }\n";
    let none = InjectedMap::default();
    let review = |action: &Action, a: &Arguments| decided(yaml, action, a, &none).verdict;
    let inside = Action::FsWrite {
        path: "/p/src/x.rs".to_owned(),
    };
    let outside = Action::FsWrite {
        path: "/p/../h/.bashrc".to_owned(),
    };
    assert_eq!(review(&inside, &Arguments::new()), Verdict::Defer);
    assert_eq!(review(&outside, &Arguments::new()), Verdict::Review);
    let web = Action::mcp("mcp__web__open");
    for (url, verdict) in [
        ("https://DOCS.example./a", Verdict::Defer),
        ("https://docs.ex%61mple/a", Verdict::Defer),
        ("https://docs.example.evil.example/a", Verdict::Review),
        ("not a url", Verdict::Review),
    ] {
        assert_eq!(review(&web, &args(&[("url", url)])), verdict, "{url}");
    }
    let chat = Action::mcp("mcp__chat__post");
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----";
    assert_eq!(review(&chat, &args(&[("text", key)])), Verdict::Review);
    assert_eq!(review(&chat, &args(&[("text", "hello")])), Verdict::Defer);
}

#[test]
fn provenance_untrusted_holds_for_a_host_the_session_read() {
    let yaml = "version: 1\ndefaults: { '*': defer }\nreview:\n  - id: planted\n    \
                mcp: ['mcp__http__*']\n    when:\n      - { arg: url, provenance: untrusted }\n";
    let mut seen = InjectedMap::default();
    let token = Token {
        kind: TokenKind::UrlHost,
        text: "collect.evil.example".to_owned(),
    };
    seen.add([token], "the page fetched from https://docs.example/x");
    let call = Action::mcp("mcp__http__post");
    let planted = args(&[("url", "https://Collect.Evil.Example/up")]);
    assert_eq!(
        decided(yaml, &call, &planted, &seen).verdict,
        Verdict::Review
    );
    let own = args(&[("url", "https://api.example/up")]);
    assert_eq!(decided(yaml, &call, &own, &seen).verdict, Verdict::Defer);
}

#[test]
fn conditions_lower_to_os_layers_as_a_wider_deny() {
    let yaml = "version: 1\ndefaults: { '*': allow }\ndeny:\n  - id: notes\n    \
                fs.write: ['/h/notes/**']\n    when:\n      - { provenance: untrusted }\n";
    let p = policy(yaml);
    let ir = crate::ir::lower(&p, &ctx()).unwrap();
    assert!(ir.fs.write.deny.iter().any(|r| r.id == "notes"));
    assert!(ir.losses.iter().any(|l| l.rule == "notes"));
    assert!(
        ir.decide_only
            .iter()
            .any(|d| d.kind == "when" && d.rules == ["notes"])
    );
}
