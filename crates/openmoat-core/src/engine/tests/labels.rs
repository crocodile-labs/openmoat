//! Data labels (ADR-126): kept by source, carried to every later sink, decided
//! only by deny and review rules.

use super::*;

/// A policy whose catch-all allows, with a broad shell allow that must not
/// take a flow out of review, and a person's rule on two flows.
const POLICY: &str = "version: 1\ndefaults: { '*': allow }\n\
     allow:\n  - id: everything\n    shell: ['*']\n\
     review:\n  - id: web-to-publish\n    shell: ['@data-flow web publish *']\n\
     \x20 - id: cross-server\n    shell: ['@data-flow mcp:* mcp-send mcp:* $']\n";

fn compiled(p: &Policy) -> CompiledPolicy<'_> {
    CompiledPolicy::compile(p, &ctx()).unwrap()
}

fn after(history: &[Action], action: &Action) -> Decision {
    let p = policy(POLICY);
    let c = compiled(&p);
    let mut taint = Taint::default();
    for earlier in history {
        taint.absorb(c.exposure(earlier, "/p", &NoResolver));
    }
    c.with_taint(c.decide(action), action, &NoResolver, &taint)
}

fn fetch(url: &str) -> Action {
    Action::Fetch {
        url: url.to_owned(),
    }
}

#[test]
fn each_source_kind_gets_its_label_first_source_wins() {
    let p = policy(POLICY);
    let c = compiled(&p);
    let mut taint = Taint::default();
    for earlier in [
        fetch("https://docs.rs/serde"),
        Action::mcp("mcp__tickets__get_issue"),
        fetch("https://evil.example/x"),
    ] {
        taint.absorb(c.exposure(&earlier, "/p", &NoResolver));
    }
    let names: Vec<&str> = taint.labels.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, ["web", "external", "mcp:tickets"]);
    assert_eq!(taint.labels[0].source, "fetch docs.rs");
}

#[test]
fn a_label_reaches_a_sink_whatever_the_words() {
    let d = after(&[fetch("https://docs.rs/x")], &shell("npm publish"));
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(d.rules.iter().any(|r| r == "web-to-publish"));
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("however it was reworded"))
    );
}

#[test]
fn allow_rules_never_take_a_flow_out_of_review() {
    // `everything` allows every shell atom, `@data-flow` ones included
    let d = after(
        &[Action::mcp("mcp__tickets__get_issue")],
        &Action::mcp("mcp__slack__post_message"),
    );
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(d.rules.iter().any(|r| r == "cross-server"));
}

#[test]
fn a_servers_own_tool_is_same_source() {
    let d = after(
        &[Action::mcp("mcp__github__get_issue")],
        &Action::mcp("mcp__github__create_pull_request"),
    );
    assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
}

#[test]
fn flow_trusted_servers_skip_the_anchored_rule_only() {
    let yaml = format!(
        "{POLICY}  - id: any-mcp-flow\n    shell: ['@data-flow mcp:* mcp-send *']\nmcp: {{ flow_trusted: [tickets] }}\n"
    );
    let p = policy(&yaml);
    let c = compiled(&p);
    let taint = c.exposure(&Action::mcp("mcp__tickets__get_issue"), "/p", &NoResolver);
    let send = Action::mcp("mcp__slack__post_message");
    let d = c.with_taint(c.decide(&send), &send, &NoResolver, &taint);
    assert!(!d.rules.iter().any(|r| r == "cross-server"), "{d:?}");
    assert!(d.rules.iter().any(|r| r == "any-mcp-flow"), "{d:?}");
}

#[test]
fn a_label_no_rule_names_changes_nothing() {
    let d = after(
        &[fetch("https://docs.rs/x")],
        &fetch("https://example.org/"),
    );
    assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
}

#[test]
fn facts_without_labels_count_as_untrusted_fail_closed() {
    // a fold from before labels, or file provenance the CLI adds
    let taint = Taint {
        untrusted: Some("a file an exposed session wrote".into()),
        seen: Some("the output of `gh issue view 1`".into()),
        secrets: vec![Secret {
            source: "read ~/.ssh/id_rsa".into(),
            host: None,
        }],
        ..Taint::default()
    };
    let names: Vec<String> = taint.label_set().into_iter().map(|l| l.name).collect();
    assert_eq!(names, ["secret", "untrusted", "external"]);
    // a labelled fold implies nothing more
    let p = policy(POLICY);
    let c = compiled(&p);
    let labelled = c.exposure(&fetch("https://docs.rs/x"), "/p", &NoResolver);
    let names: Vec<String> = labelled.label_set().into_iter().map(|l| l.name).collect();
    assert_eq!(names, ["web", "external"]);
}

#[test]
fn labels_survive_a_round_trip_and_older_rows_read_without_them() {
    let p = policy(POLICY);
    let c = compiled(&p);
    let taint = c.exposure(&Action::mcp("mcp__tickets__get_issue"), "/p", &NoResolver);
    let json = serde_json_like(&taint);
    assert!(json.contains("mcp:tickets"));
    let older: Taint = crate::yaml::from_str("secrets: []\nuntrusted: fetch x\n").unwrap();
    assert_eq!(older.labels, []);
    assert_eq!(older.label_set()[0].name, "untrusted");
}

/// The taint as YAML, the one serialiser the core has.
fn serde_json_like(taint: &Taint) -> String {
    crate::yaml::to_string(taint).unwrap()
}
