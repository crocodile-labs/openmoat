use openmoat_core::DEFAULT_POLICY;
use serde_json::{Value, json};

use super::super::Generated;
use super::super::settings::{apply, in_sync, remove};
use super::super::tests::generated;

/// The default policy's settings with `rules` as the `permissions.deny` rules.
fn with_rules(rules: &[&str]) -> Generated {
    let mut out = generated(DEFAULT_POLICY);
    out.deny_rules = rules.iter().map(|r| (*r).to_owned()).collect();
    out
}

/// `moat uninstall` takes exactly the deny rules OpenMoat added: a user's rule
/// spelled like one of them stays, and the file comes back byte for byte.
#[test]
fn uninstall_removes_exactly_the_deny_rules_it_added() {
    let out = with_rules(&["Read(//Users/me/.ssh)", "Edit(//Users/me/.moat)"]);
    let original = json!({
        "permissions": { "deny": ["Read(//Users/me/.ssh)", "Edit(//tmp/x)", "Bash(rm *)"] },
        "theme": "dark",
    });
    let text = |v: &Value| serde_json::to_string_pretty(v).unwrap();
    let mut root = original.clone();
    let mut owned = Vec::new();
    assert!(apply(&mut root, &out, &mut owned).unwrap());
    assert_eq!(
        owned,
        ["Edit(//Users/me/.moat)"],
        "the user's rule is not ours"
    );
    assert!(in_sync(&root, &out, &owned));
    assert!(!apply(&mut root, &out, &mut owned).unwrap(), "idempotent");
    assert!(remove(&mut root, &owned));
    assert_eq!(text(&root), text(&original));
}

/// A rule OpenMoat added that the policy no longer produces is out of sync,
/// and the next apply takes it.
#[test]
fn a_rule_the_policy_dropped_goes_on_the_next_apply() {
    let out = with_rules(&["Edit(//Users/me/.moat)"]);
    let mut root = json!({ "permissions": { "deny": ["Read(//Users/me/.old)", "Bash(rm *)"] } });
    let mut owned = vec!["Read(//Users/me/.old)".to_owned()];
    assert!(!in_sync(&root, &out, &owned));
    apply(&mut root, &out, &mut owned).unwrap();
    assert!(in_sync(&root, &out, &owned));
    assert_eq!(
        root["permissions"]["deny"],
        json!(["Bash(rm *)", "Edit(//Users/me/.moat)"])
    );
}
