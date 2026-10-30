//! `fetch`: a narrower kind of `net` for a host fetch tool (ADR-017).

use super::*;

fn fetch(url: &str) -> Action {
    Action::Fetch {
        url: url.to_owned(),
    }
}

fn verdict_and_rules(p: &Policy, action: &Action) -> (Verdict, Vec<String>) {
    let d = evaluate(p, &ctx(), action).unwrap();
    (d.verdict, d.rules)
}

#[test]
fn fetch_is_a_narrower_kind_of_net() {
    let p = policy(
        "version: 1\ndefaults: { net: deny, fetch: ask }\n\
         deny:\n  - id: metadata\n    net: ['169.254.169.254']\n\
         allow:\n  - id: registries\n    net: ['crates.io']\n  - id: docs\n    fetch: ['docs.rs']\n\
         ask:\n  - id: local\n    net: ['localhost']\n",
    );
    let cases = [
        (
            fetch("http://169.254.169.254/latest"),
            Verdict::Deny,
            "metadata",
        ),
        (fetch("https://CRATES.io/x"), Verdict::Allow, "registries"),
        (fetch("https://docs.rs/serde"), Verdict::Allow, "docs"),
        (fetch("http://localhost:3000/"), Verdict::Ask, "local"),
        (
            fetch("https://unknown.example/"),
            Verdict::Ask,
            "default.fetch",
        ),
        // a curl that sends nothing is a fetch (ADR-035); one that can send data is `net`
        // the fetch allow covers the host; the command itself takes this policy's default
        (
            shell("curl -q https://docs.rs/serde"),
            Verdict::Ask,
            "default",
        ),
        // a download is that fetch plus the write of the file it saves
        (
            shell("curl -sSL -o serde.html https://docs.rs/serde"),
            Verdict::Ask,
            "default",
        ),
        (
            shell("curl -d x=1 https://docs.rs/serde"),
            Verdict::Deny,
            "default.net",
        ),
        (
            shell("curl -T f https://unknown.example/"),
            Verdict::Deny,
            "default.net",
        ),
    ];
    for (action, verdict, rule) in cases {
        let got = verdict_and_rules(&p, &action);
        assert_eq!(got, (verdict, vec![rule.to_owned()]), "{action:?}");
    }
}

#[test]
fn fetch_deny_list_never_catches_other_network_access() {
    let p = policy(
        "version: 1\ndefaults: allow\ndeny:\n  - id: no-fetch\n    fetch: ['*.example']\n\
         allow:\n  - id: also\n    fetch: ['a.example']\n",
    );
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://a.example/")),
        (Verdict::Deny, vec!["no-fetch".to_owned()]),
        "deny stays absolute for fetches"
    );
    assert_eq!(
        verdict_and_rules(&p, &shell("curl -d x=1 https://a.example/")).0,
        Verdict::Allow
    );
    // a curl that sends nothing is a fetch (ADR-035), so the fetch deny catches it
    assert_eq!(
        verdict_and_rules(&p, &shell("curl -q https://a.example/")).0,
        Verdict::Deny
    );
}

#[test]
fn fetch_defaults_fall_back_to_net() {
    let p = policy("version: 1\ndefaults: { net: deny, '*': allow }\n");
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://unknown.example/")),
        (Verdict::Deny, vec!["default.net".to_owned()])
    );
    let p = policy("version: 1\ndefaults: allow\n");
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://")),
        (Verdict::Defer, vec!["unparseable".to_owned()])
    );
}

/// An MCP call that only opens a page (`opens`, ADR-047) is a fetch of a plain
/// web page, so `fetch` rules and `defaults.fetch` decide it; under
/// `mcp.browser_open: net` it is a `net` connection, as before.
#[test]
fn a_page_open_is_a_fetch_unless_the_policy_says_net() {
    let open = |url: &str| {
        let mut action = Action::mcp("mcp__playwright__browser_navigate");
        if let Action::McpTool { opens, .. } = &mut action {
            opens.push(url.to_owned());
        }
        action
    };
    let rules = "defaults: { '*': defer, net: deny, fetch: defer }\n\
                 allow:\n  - id: docs\n    fetch: ['docs.rs']\n";
    let as_fetch = policy(&format!("version: 1\n{rules}"));
    let as_net = policy(&format!(
        "version: 1\nmcp: {{ browser_open: net }}\n{rules}"
    ));
    assert!(as_fetch.browser_open_is_fetch());
    assert!(!as_net.browser_open_is_fetch());
    let unlisted = open("https://example.org/");
    assert_eq!(verdict_and_rules(&as_fetch, &unlisted).0, Verdict::Defer);
    assert_eq!(
        verdict_and_rules(&as_net, &unlisted),
        (Verdict::Deny, vec!["default.net".to_owned()])
    );
    // a `fetch` allow covers the page, never the strict `net` reading of it
    assert_eq!(
        verdict_and_rules(&as_fetch, &open("https://docs.rs/")).0,
        Verdict::Defer
    );
    assert_eq!(
        verdict_and_rules(&as_net, &open("https://docs.rs/")).0,
        Verdict::Deny
    );
    assert!(Policy::parse("version: 1\nmcp: { browser_open: always }\n").is_err());
}
