use std::collections::BTreeSet;

use super::*;
use crate::{DEFAULT_POLICY, Kind, Policy};

fn default_policy() -> Policy {
    Policy::parse(DEFAULT_POLICY).unwrap()
}

/// Every id OpenMoat's code names, from every table.
fn every_id() -> Vec<&'static str> {
    BUILTIN_RULES
        .iter()
        .map(|r| r.id)
        .chain(crate::diffscan::RULES.iter().map(|r| r.id))
        .chain(POLICY_RULES.iter().copied())
        .chain([DEFAULT, DEFAULT_NET])
        .collect()
}

#[test]
fn every_id_is_written_once() {
    let ids = every_id();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "an id repeats: {ids:?}");
}

/// Each id can have its page (`rule_page` in `openmoat-hosts` takes only
/// these characters).
#[test]
fn every_id_is_a_plain_page_name() {
    for id in every_id() {
        assert!(
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b)),
            "{id}"
        );
    }
}

#[test]
fn the_policy_rules_the_code_names_are_in_the_default_policy() {
    let policy = default_policy();
    for id in POLICY_RULES {
        assert!(policy.own_group(id).is_some(), "{id} is not a default rule");
    }
}

/// A builtin id that were also a policy group would take the group's words
/// and page, and the two could not be told apart in the audit log.
#[test]
fn no_builtin_rule_is_a_policy_rule() {
    let policy = default_policy();
    for rule in BUILTIN_RULES {
        assert!(policy.own_group(rule.id).is_none(), "{}", rule.id);
    }
    for rule in crate::diffscan::RULES {
        assert!(policy.own_group(rule.id).is_none(), "{}", rule.id);
    }
}

#[test]
fn the_default_net_rule_is_the_default_for_net() {
    assert_eq!(
        DEFAULT_NET,
        format!("{DEFAULT_PREFIX}{}", Kind::Net.as_str())
    );
    let defaults = crate::Defaults::PerKind([("net".to_owned(), Verdict::Deny)].into());
    assert_eq!(defaults.for_kind(Kind::Net).1, DEFAULT_NET);
}

#[test]
fn resolves_policy_groups_defaults_and_builtin_rules_only() {
    let policy = default_policy();
    for id in [
        KERNEL_SELF,
        UNPARSEABLE,
        DEFAULT,
        DEFAULT_NET,
        PROXY_SESSION,
    ] {
        assert!(resolves(id, &policy), "{id}");
    }
    for id in ["default.nothing", "no-such-rule", "", "pack:x:y"] {
        assert!(!resolves(id, &policy), "{id}");
    }
}

#[test]
fn words_are_found_by_id() {
    assert_eq!(words(UNPARSEABLE).map(|w| w.why), Some(UNPARSEABLE_WHY));
    assert!(words(APPROVED_SESSION).is_none());
    assert!(words(KERNEL_SELF).is_none());
}

const UNPARSEABLE_WHY: &str = "what OpenMoat cannot read, it cannot check";
