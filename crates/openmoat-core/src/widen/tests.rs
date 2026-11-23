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
