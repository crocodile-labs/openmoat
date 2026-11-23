use super::*;

fn ctx() -> EvalContext {
    EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    }
}

fn compare_yaml(old: &str, new: &str) -> Report {
    let (old, new) = (Policy::parse(old).unwrap(), Policy::parse(new).unwrap());
    compare(&old, &new, &[ctx()], &[]).unwrap()
}

fn outcome(report: &Report, kind: &str) -> Outcome {
    report
        .proof
        .iter()
        .find(|p| p.kind == kind)
        .map(|p| p.outcome.clone())
        .unwrap()
}

const BASE: &str = "version: 1\ndefaults: { '*': review, net: deny, fs.read: defer }\n\
    deny:\n  - id: keys\n    fs.read: ['~/.ssh/**', '!~/.ssh/known_hosts']\n\
    allow:\n  - id: dev\n    shell: ['git status']\n    fs.read: ['${project}/**']\n    net: ['github.com']\n";

#[test]
fn the_same_policy_is_proven_not_to_widen() {
    let report = compare_yaml(BASE, BASE);
    assert!(!report.widens(), "{report:#?}");
    assert!(report.rules.is_empty() && report.settings.is_empty());
    for p in &report.proof {
        assert_eq!(p.outcome, Outcome::Proven, "{p:?}");
    }
}

#[test]
fn a_narrower_deny_rule_is_found_by_the_search() {
    // `~/.ssh/**` becomes `~/.ssh/id_*`: `~/.ssh/config` is no longer denied.
    let new = BASE.replace("'~/.ssh/**'", "'~/.ssh/id_*'");
    let report = compare_yaml(BASE, &new);
    assert!(report.widens());
    assert_eq!(outcome(&report, "fs.read"), Outcome::Widens);
    let w = report
        .widenings
        .iter()
        .find(|w| w.case.starts_with("read /Users/me/.ssh/"))
        .unwrap();
    assert_eq!(
        (w.before, w.after),
        (Verdict::Deny, Verdict::Defer),
        "{w:?}"
    );
    assert_eq!(w.before_rules, ["keys"]);
    assert_eq!(report.rules[0].change, "changed");
}

#[test]
fn a_pure_narrowing_passes() {
    let new = BASE.replace("'~/.ssh/**', ", "'~/.ssh/**', '~/.aws/**', ");
    let report = compare_yaml(BASE, &new);
    assert!(!report.widens(), "{:#?}", report.widenings);
    assert_eq!(outcome(&report, "fs.read"), Outcome::Proven);
}

#[test]
fn a_lookalike_host_and_a_changed_default_are_found() {
    let new = BASE.replace("['github.com']", "['*github.com']");
    let report = compare_yaml(BASE, &new);
    assert!(
        report
            .widenings
            .iter()
            .any(|w| w.case.contains("github.com") && w.after == Verdict::Allow),
        "{:#?}",
        report.widenings
    );
    let new = BASE.replace("net: deny", "net: review");
    let report = compare_yaml(BASE, &new);
    assert!(
        report
            .settings
            .iter()
            .any(|c| c.setting == "defaults.net" && c.effect == Effect::Widens)
    );
    assert_eq!(outcome(&report, "net"), Outcome::Widens);
}

#[test]
fn a_removed_exclusion_widens_and_an_added_one_narrows_no_further() {
    // Dropping `!~/.ssh/known_hosts` denies more: no widening.
    let new = BASE.replace(", '!~/.ssh/known_hosts'", "");
    assert!(!compare_yaml(BASE, &new).widens());
    // The reverse lets known_hosts fall to the default.
    let report = compare_yaml(&new, BASE);
    assert!(
        report
            .widenings
            .iter()
            .any(|w| w.case.ends_with("known_hosts")),
        "{report:#?}"
    );
}

#[test]
fn shell_rules_are_checked_over_generated_cases() {
    let new = BASE.replace("['git status']", "['git *']");
    let report = compare_yaml(BASE, &new);
    let shell: Vec<_> = report
        .widenings
        .iter()
        .filter(|w| w.case.starts_with("shell"))
        .collect();
    assert!(!shell.is_empty(), "{report:#?}");
    assert!(shell.iter().all(|w| w.after_rules == ["dev"]));
}

#[test]
fn request_rules_are_checked_over_methods_and_paths() {
    let with = |rules: &str| {
        format!("{BASE}requests:\n  - id: gh\n    host: api.github.com\n    deny: [{rules}]\n")
    };
    let report = compare_yaml(&with("'POST /gists', 'DELETE /**'"), &with("'POST /gists'"));
    assert!(
        report
            .widenings
            .iter()
            .any(|w| w.case.starts_with("DELETE https://api.github.com/")),
        "{:#?}",
        report.widenings
    );
    let report = compare_yaml(&with("'POST /gists'"), &with("'POST /gists', 'PUT /**'"));
    assert!(report.widenings.is_empty(), "{:#?}", report.widenings);
}

#[test]
fn settings_are_ranked() {
    let new = format!(
        "{BASE}sandbox:\n  read_roots: ['/opt/tools']\nexecutables:\n  git: ['/usr/bin/git']\n"
    );
    let report = compare_yaml(BASE, &new);
    assert!(
        report
            .settings
            .iter()
            .any(|c| c.setting == "sandbox.read_roots" && c.effect == Effect::Widens)
    );
    assert!(
        report
            .settings
            .iter()
            .any(|c| c.setting == "executables.git" && c.effect == Effect::Narrows)
    );
    let back = compare_yaml(&new, BASE);
    assert!(
        back.settings
            .iter()
            .any(|c| c.setting == "executables.git" && c.effect == Effect::Widens)
    );
}

/// A review group the old policy lacks, with an exclusion, only holds more
/// where the kind's default is not `deny`: proven, without a widening.
#[test]
fn a_new_review_group_with_an_exclusion_is_proven_to_narrow() {
    let new = format!(
        "{BASE}review:\n  - id: system\n    fs.write: ['/usr/**', '!/usr/local/**']\n    \
         fs.read: ['/etc/**', '!/etc/hosts']\n"
    );
    let report = compare_yaml(BASE, &new);
    assert!(!report.widens(), "{:#?}", report.widenings);
    assert_eq!(outcome(&report, "fs.write"), Outcome::Proven);
    assert_eq!(outcome(&report, "fs.read"), Outcome::Proven);
}

/// Where the default is `deny`, a review rule lets through what the default
/// denied: the search still finds it, and an exclusion added to a deny group
/// still widens.
#[test]
fn a_review_rule_under_a_deny_default_and_a_new_exclusion_widen() {
    let new = format!("{BASE}review:\n  - id: some-hosts\n    net: ['example.org']\n");
    let report = compare_yaml(BASE, &new);
    assert_eq!(outcome(&report, "net"), Outcome::Widens);
    assert!(
        report
            .widenings
            .iter()
            .any(|w| w.case.contains("example.org") && w.after == Verdict::Review),
        "{:#?}",
        report.widenings
    );
    let new = BASE.replace(
        "'!~/.ssh/known_hosts'",
        "'!~/.ssh/known_hosts', '!~/.ssh/config'",
    );
    let report = compare_yaml(BASE, &new);
    assert_eq!(outcome(&report, "fs.read"), Outcome::Widens);
}

/// The settings ADR-108 and ADR-109 add: `sandbox.strict` off and
/// `hooks.foreign: warn` are the wider values.
#[test]
fn strict_and_foreign_hooks_are_ranked() {
    let strict = format!("{BASE}sandbox:\n  strict: true\nhooks:\n  foreign: hold\n");
    let effect = |report: &Report, setting: &str| {
        report
            .settings
            .iter()
            .find(|c| c.setting == setting)
            .map(|c| c.effect)
    };
    let narrowed = compare_yaml(BASE, &strict);
    assert_eq!(effect(&narrowed, "sandbox.strict"), Some(Effect::Narrows));
    assert_eq!(effect(&narrowed, "hooks.foreign"), Some(Effect::Narrows));
    assert!(!narrowed.widens(), "{narrowed:#?}");
    let widened = compare_yaml(&strict, BASE);
    assert_eq!(effect(&widened, "sandbox.strict"), Some(Effect::Widens));
    assert_eq!(effect(&widened, "hooks.foreign"), Some(Effect::Widens));
    assert!(widened.widens());
}

#[test]
fn conformance_files_are_read_as_calls() {
    let probes = fixtures(
        "- id: a\n  threat: T1\n  action: { shell: \"cat x\" }\n  expect: { verdict: deny }\n\
         - id: b\n  action: { mcp_tool: { name: mcp__s__t, reads: [x] } }\n  expect: { verdict: review }\n\
         - id: c\n  action: { unknown_tool: { host: h, tool: t } }\n  expect: { verdict: review }\n",
    )
    .unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[1].source, WideningSource::Fixture("b".into()));
}

/// A class the samples fill with its first member only: the search still
/// finds the one character the new policy no longer denies.
#[test]
fn the_search_finds_what_no_sample_reaches() {
    let old = BASE.replace("'~/.ssh/**', ", "'~/.ssh/**', '/data/[a-m]*/secret', ");
    let new = BASE.replace("'~/.ssh/**', ", "'~/.ssh/**', '/data/[a-k]*/secret', ");
    let report = compare_yaml(&old, &new);
    let proof: Vec<_> = report
        .widenings
        .iter()
        .filter(|w| w.source == WideningSource::Proof("fs.read"))
        .collect();
    assert_eq!(proof.len(), 1, "{report:#?}");
    assert!(proof[0].case.starts_with("read /data/l"), "{proof:?}");
    assert!(
        report
            .widenings
            .iter()
            .all(|w| w.source == WideningSource::Proof("fs.read")),
        "the samples alone miss it: {report:#?}"
    );
}

fn effect(report: &Report, setting: &str) -> Option<Effect> {
    report
        .settings
        .iter()
        .find(|c| c.setting == setting)
        .map(|c| c.effect)
}

/// The lethal trifecta's keys (ADR-113): `deny` holds more than `review`, a
/// private path gone holds less.
#[test]
fn taint_keys_are_ranked() {
    let with = |taint: &str| format!("{BASE}taint: {taint}\n");
    let deny = with("{ trifecta: deny, private_paths: ['~/notes/**'] }");
    let report = compare_yaml(BASE, &deny);
    assert_eq!(effect(&report, "taint.trifecta"), Some(Effect::Narrows));
    assert_eq!(
        effect(&report, "taint.private_paths"),
        Some(Effect::Narrows)
    );
    assert!(!report.widens() && !report.unchecked(), "{report:#?}");
    let back = compare_yaml(&deny, BASE);
    assert_eq!(effect(&back, "taint.trifecta"), Some(Effect::Widens));
    assert_eq!(effect(&back, "taint.private_paths"), Some(Effect::Widens));
    let review = with("{ trifecta: review, private_paths: ['~/notes/**'] }");
    let lower = compare_yaml(&deny, &review);
    assert_eq!(effect(&lower, "taint.trifecta"), Some(Effect::Widens));
    assert_eq!(effect(&lower, "taint.private_paths"), None);
    // `review` written out is the default: nothing changed.
    let written = compare_yaml(BASE, &with("{ trifecta: review }"));
    assert_eq!(written.settings, []);
}

const MAIL: &str = "version: 1\ndefaults: { '*': defer }\n\
    deny:\n  - id: mail\n    mcp: ['mcp__mail__send_email']\n";
const MAIL_WHEN: &str = "    when:\n      - { arg: to, not_in: ['*@example.com'] }\n";

/// `when` conditions only narrow a deny rule (ADR-113): adding one to a rule
/// that held every call widens; the search reads the old policy's as met and
/// the new policy's as unmet, and conditions both have alike stay proven.
#[test]
fn when_conditions_are_searched_on_the_safe_side() {
    let conditional = format!("{MAIL}{MAIL_WHEN}");
    let report = compare_yaml(MAIL, &conditional);
    assert_eq!(outcome(&report, "mcp"), Outcome::Widens, "{report:#?}");
    assert!(report.widens());
    assert_eq!(
        report
            .rules
            .iter()
            .map(|r| r.change.as_str())
            .collect::<Vec<_>>(),
        ["changed"]
    );
    let same = compare_yaml(&conditional, &conditional);
    assert!(!same.widens());
    assert_eq!(outcome(&same, "mcp"), Outcome::Proven);
    let back = compare_yaml(&conditional, MAIL);
    assert!(!back.widens(), "{back:#?}");
    assert_eq!(outcome(&back, "mcp"), Outcome::Proven);
    // Another condition: the old one may have held calls the new one passes.
    let other = conditional.replace("*@example.com", "*@example.org");
    let changed = compare_yaml(&conditional, &other);
    assert_ne!(outcome(&changed, "mcp"), Outcome::Proven, "{changed:#?}");
}
