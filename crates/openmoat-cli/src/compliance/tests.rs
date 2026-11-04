use std::collections::BTreeSet;
use std::str::FromStr as _;

use openmoat_core::{DEFAULT_POLICY, Kind, Policy};

use super::{CONTROLS, Covers, Framework, GROUPS, group_of, groups_for};

fn default_policy() -> Policy {
    Policy::parse(DEFAULT_POLICY).unwrap()
}

fn policy_ids(groups: &[openmoat_core::RuleGroup]) -> BTreeSet<String> {
    groups.iter().map(|g| g.id.clone()).collect()
}

/// The rows of `docs/POLICY.md` §5.1, the rule ids the code adds itself.
fn built_in_table() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/POLICY.md");
    let text = std::fs::read_to_string(path).unwrap();
    let start = text
        .find("### 5.1 Rule ids that are not in your policy")
        .unwrap();
    let rest = &text[start..];
    let end = rest.find("### 5.2").unwrap();
    rest[..end].to_owned()
}

#[test]
fn every_mapped_rule_is_a_default_policy_rule_or_a_documented_built_in() {
    let policy = default_policy();
    let restrictive: BTreeSet<String> = policy_ids(&policy.deny)
        .into_iter()
        .chain(policy_ids(&policy.review))
        .collect();
    let permissive: BTreeSet<String> = policy_ids(&policy.allow)
        .into_iter()
        .chain(policy_ids(&policy.defer))
        .collect();
    let table = built_in_table();
    for group in GROUPS {
        for id in group.rule_ids() {
            // An allow or defer rule decides that a call may run: no evidence
            // of a control restricting it.
            assert!(!permissive.contains(*id), "{}: `{id}` permits", group.id);
            if restrictive.contains(*id) {
                continue;
            }
            let documented = table.contains(&format!("`{id}`"))
                || id
                    .strip_prefix("default.")
                    .is_some_and(|kind| Kind::from_str(kind).is_ok());
            assert!(
                documented,
                "{}: `{id}` is neither a deny or review rule of the default policy nor in POLICY.md §5.1",
                group.id
            );
        }
    }
}

#[test]
fn every_deny_and_ask_rule_of_the_default_policy_is_mapped() {
    let policy = default_policy();
    for rule in policy.deny.iter().chain(&policy.review) {
        assert!(
            group_of(&rule.id).is_some(),
            "default rule `{}` is in no group of compliance.rs",
            rule.id
        );
    }
}

#[test]
fn no_rule_group_or_control_is_listed_twice() {
    let mut rules = BTreeSet::new();
    let mut groups = BTreeSet::new();
    for group in GROUPS {
        assert!(groups.insert(group.id), "group `{}` twice", group.id);
        for id in group.rule_ids() {
            assert!(rules.insert(*id), "rule `{id}` in two groups");
        }
        let mut controls = BTreeSet::new();
        for control in group.controls {
            assert!(
                controls.insert((control.framework, control.id)),
                "{}: {} twice",
                group.id,
                control.id
            );
        }
        if let Covers::Rules(ids) = group.covers {
            assert!(!ids.is_empty(), "{}: no rules", group.id);
        }
        assert!(!group.controls.is_empty(), "{}: no controls", group.id);
    }
    let mut ids = BTreeSet::new();
    for control in CONTROLS {
        assert!(
            ids.insert((control.framework, control.id)),
            "{}",
            control.id
        );
    }
}

fn well_formed(framework: Framework, id: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match framework {
        Framework::OwaspLlm2025 => id
            .strip_prefix("LLM")
            .and_then(|rest| rest.strip_suffix(":2025"))
            .and_then(|n| n.parse::<u8>().ok().filter(|_| n.len() == 2))
            .is_some_and(|n| (1..=10).contains(&n)),
        Framework::Soc2 => id
            .strip_prefix("CC")
            .and_then(|rest| rest.split_once('.'))
            .is_some_and(|(series, n)| {
                digits(series) && digits(n) && (1..=9).contains(&series.parse::<u8>().unwrap_or(0))
            }),
        Framework::Iso27001 => id
            .strip_prefix("A.")
            .and_then(|rest| rest.split_once('.'))
            .is_some_and(|(theme, n)| {
                matches!(theme, "5" | "6" | "7" | "8")
                    && digits(n)
                    && !n.starts_with('0')
                    && n.parse::<u8>().is_ok_and(|n| match theme {
                        "5" => n <= 37,
                        "6" => n <= 8,
                        "7" => n <= 14,
                        _ => n <= 34,
                    })
            }),
    }
}

#[test]
fn every_control_id_is_well_formed_and_listed() {
    for group in GROUPS {
        for control in group.controls {
            assert!(
                well_formed(control.framework, control.id),
                "{}: `{}` is not a {} id",
                group.id,
                control.id,
                control.framework.name()
            );
            assert_ne!(control.title, "");
            assert!(
                CONTROLS.contains(control),
                "{}: `{}` is not in CONTROLS",
                group.id,
                control.id
            );
        }
    }
    for control in CONTROLS {
        assert!(
            groups_for(control).next().is_some(),
            "`{}` is listed but no group maps to it",
            control.id
        );
    }
}

#[test]
fn well_formed_rejects_near_misses() {
    for (framework, id) in [
        (Framework::OwaspLlm2025, "LLM11:2025"),
        (Framework::OwaspLlm2025, "LLM2:2025"),
        (Framework::OwaspLlm2025, "LLM02"),
        (Framework::Soc2, "CC6"),
        (Framework::Soc2, "C6.1"),
        (Framework::Iso27001, "A.8.35"),
        (Framework::Iso27001, "A.9.1"),
        (Framework::Iso27001, "A.8.03"),
    ] {
        assert!(!well_formed(framework, id), "{id}");
    }
}

#[test]
fn matching_is_by_exact_rule_id() {
    let secrets = GROUPS.iter().find(|g| g.id == "secrets").unwrap();
    assert!(secrets.matches(&["default", "secrets-paths"]));
    assert!(!secrets.matches(&["repo:secrets-paths"]));
    assert!(!secrets.matches::<&str>(&[]));
    let log = GROUPS.iter().find(|g| g.id == "audit-log").unwrap();
    assert!(log.matches::<&str>(&[]));
}
