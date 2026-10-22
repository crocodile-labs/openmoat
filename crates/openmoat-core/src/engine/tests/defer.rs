//! `defer` (ADR-025): no objection and no approval; the agent's own prompt decides.

use super::*;

fn decided(p: &Policy, command: &str) -> (Verdict, Vec<String>) {
    let d = evaluate(p, &ctx(), &shell(command)).unwrap();
    (d.verdict, d.rules)
}

#[test]
fn a_word_that_looks_like_a_host_gets_the_catch_all_not_the_net_default() {
    let p = policy("version: 1\ndefaults: { '*': defer, net: deny }\n");
    let defer = (Verdict::Defer, vec!["default".to_owned()]);
    assert_eq!(decided(&p, "echo check_runs.0.id"), defer);
    let net = (Verdict::Deny, vec!["default.net".to_owned()]);
    assert_eq!(decided(&p, "curl check_runs.0.id"), net);
    // never `allow`, and never a deny that nothing named
    let echo = "allow:\n  - id: echo\n    shell: ['echo *']\n";
    let p = policy(&format!(
        "version: 1\ndefaults: {{ '*': allow, net: deny }}\n{echo}"
    ));
    assert_eq!(decided(&p, "echo app.dev").0, Verdict::Defer);
    let p = policy(&format!(
        "version: 1\ndefaults: {{ '*': deny, net: deny }}\n{echo}"
    ));
    assert_eq!(decided(&p, "echo app.dev").0, Verdict::Ask);
}

#[test]
fn net_rules_still_match_a_word_that_looks_like_a_host() {
    let p = policy(
        "version: 1\ndefaults: { '*': defer, net: deny }\ndeny:\n  - id: evil\n    \
         net: ['evil.example.com']\nallow:\n  - id: docs\n    net: ['docs.rs']\n    shell: ['echo *']\n",
    );
    assert_eq!(
        decided(&p, "python3 x.py evil.example.com"),
        (Verdict::Deny, vec!["evil".to_owned()])
    );
    assert_eq!(decided(&p, "echo docs.rs").0, Verdict::Allow);
}

#[test]
fn defer_rules_sit_between_ask_and_the_defaults() {
    let p = policy(
        "version: 1\ndefaults: deny\nask:\n  - id: q\n    shell: ['make deploy']\n\
         defer:\n  - id: d\n    shell: ['make *']\n",
    );
    assert_eq!(
        decided(&p, "make deploy"),
        (Verdict::Ask, vec!["q".to_owned()])
    );
    assert_eq!(
        decided(&p, "make test"),
        (Verdict::Defer, vec!["d".to_owned()])
    );
    assert_eq!(decided(&p, "rm x").0, Verdict::Deny);
    // the strictest atom still wins: a defer never softens a deny
    assert_eq!(decided(&p, "make test && rm x").0, Verdict::Deny);
}

#[test]
fn a_mail_address_in_its_option_is_no_host_the_command_connects_to() {
    let p = policy(
        "version: 1\ndefaults: { '*': allow, net: deny }\nallow:\n  - id: gh\n    \
         net: ['github.com']\n",
    );
    for command in [
        "git -c user.email=1+a@users.noreply.github.com push https://github.com/a/b main",
        "curl -u me@example.org:token https://github.com/x",
        "curl -d email=me@example.org https://github.com/x",
        "curl -H 'From: me@example.org' https://github.com/x",
    ] {
        assert_eq!(decided(&p, command).0, Verdict::Allow, "{command}");
    }
    // the same words where the command connects to them
    for command in [
        "ssh me@example.org",
        "curl me@example.org",
        "curl a=me@example.org",
        "git -c http.proxy=me@example.org push https://github.com/a/b main",
        "curl -d u=me@example.org:443 https://github.com/x",
    ] {
        assert_eq!(
            decided(&p, command),
            (Verdict::Deny, vec!["default.net".to_owned()]),
            "{command}"
        );
    }
}

#[test]
fn a_mail_address_in_interpreter_code_only_looks_like_a_host() {
    let p = policy(
        "version: 1\ndefaults: { '*': defer, net: deny }\ndeny:\n  - id: evil\n    \
         net: ['evil.example.com']\n",
    );
    let code = |s: &str| format!("python3 -c 'import json; json.dump({{\"email\": \"{s}\"}}, f)'");
    assert_eq!(
        decided(&p, &code("1+a@users.noreply.github.com")),
        (Verdict::Defer, vec!["default".to_owned()])
    );
    // a net rule that names the domain still matches
    assert_eq!(
        decided(&p, &code("me@evil.example.com")),
        (Verdict::Deny, vec!["evil".to_owned()])
    );
    // a URL, a host with a port and a plain host in a string are still hosts
    for s in ["https://me@other.com/x", "me@other.com:22", "other.com"] {
        assert_eq!(
            decided(&p, &code(s)),
            (Verdict::Deny, vec!["default.net".to_owned()]),
            "{s}"
        );
    }
}
