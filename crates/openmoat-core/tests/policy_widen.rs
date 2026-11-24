//! The never-widen check (ADR-111) on the shipped default policy, over every
//! conformance fixture: the upgrade from the 0.24.0 default only narrows, a
//! defer → allow change of the kind that once shipped a bypass is reported
//! case by case, and a pure narrowing passes.

use std::fs;
use std::path::Path;

use openmoat_core::widen::{self, Outcome, Probe, Report, WideningSource};
use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy, RuleGroup, Verdict};

/// The default policy as OpenMoat 0.24.0 shipped it.
const DEFAULT_V0_24_0: &str = include_str!("policy_widen/default-v0.24.0.yaml");

fn contexts() -> Vec<EvalContext> {
    let ctx = |home: &str, project: &str, case_insensitive_paths| EvalContext {
        home: home.into(),
        project: Some(project.into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project.into(),
        case_insensitive_paths,
    };
    vec![
        ctx("/Users/me", "/p", false),
        ctx("/home/dev", "/home/dev/src/app", true),
    ]
}

/// Every conformance fixture, as calls.
fn corpus() -> Vec<Probe> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance");
    let mut out = Vec::new();
    for name in ["attacks.yaml", "benign.yaml", "review.yaml"] {
        let text = fs::read_to_string(dir.join(name)).unwrap();
        out.extend(widen::fixtures(&text).unwrap());
    }
    assert!(out.len() > 500, "only {} fixtures were read", out.len());
    out
}

/// Both policies over every conformance fixture, in both contexts.
fn compare(old: &Policy, new: &Policy) -> Report {
    widen::compare(old, new, &contexts(), &corpus()).unwrap()
}

/// Both policies over the generated cases and the search only, in one context.
fn compare_rules(old: &Policy, new: &Policy) -> Report {
    widen::compare(old, new, &contexts()[..1], &[]).unwrap()
}

fn default() -> Policy {
    Policy::parse(DEFAULT_POLICY).unwrap()
}

#[test]
fn the_default_policy_is_proven_against_itself() {
    let report = compare_rules(&default(), &default());
    assert!(
        !report.widens() && !report.unchecked(),
        "{:#?}",
        report.widenings
    );
    for p in &report.proof {
        assert_eq!(p.outcome, Outcome::Proven, "{p:?}");
    }
}

/// 0.25.0 added `ps` environment dumps to `env-dump` and the decoy-key record
/// to `kernel-self`; since then `kernel-self` also names the audit signing key
/// and `hooks accept` (ADR-109, ADR-110), and the outside benchmarks' gaps
/// (ADR-112) grew `secrets-paths` and `persistence` and added three review
/// rules, and staging holds a send of packed or private data (ADR-113,
/// `staging-egress`), and a line written to hide what it runs is held
/// (ADR-116, `obfuscated`), and one MCP server's data sent through another
/// server's acting tool is held (ADR-126, `data-flow`). Every change holds
/// more, nothing else.
#[test]
fn the_upgrade_from_the_0_24_default_only_narrows() {
    let old = Policy::parse(DEFAULT_V0_24_0).unwrap();
    let report = compare(&old, &default());
    assert!(report.widenings.is_empty(), "{:#?}", report.widenings);
    assert!(report.settings.is_empty(), "{:#?}", report.settings);
    let changed: Vec<(&str, &str, &str)> = report
        .rules
        .iter()
        .map(|r| (r.list, r.id.as_str(), r.change.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("deny", "env-dump", "changed"),
            ("deny", "kernel-self", "changed"),
            ("review", "persistence", "changed"),
            ("deny", "secrets-paths", "changed"),
            ("review", "credential-egress", "added"),
            ("review", "data-flow", "added"),
            ("review", "obfuscated", "added"),
            ("review", "staging-egress", "added"),
            ("review", "stops-system", "added"),
            ("review", "system-files", "added")
        ]
    );
    for p in &report.proof {
        assert_eq!(p.outcome, Outcome::Proven, "{p:?}");
    }
}

/// The reverse of the upgrade above is a widening the check names: the
/// decoy-key record readable again. Its own test, so it runs beside the
/// upgrade's rather than after it.
#[test]
fn the_downgrade_to_the_0_24_default_widens() {
    let old = Policy::parse(DEFAULT_V0_24_0).unwrap();
    let back = compare_rules(&default(), &old);
    assert!(
        back.widenings
            .iter()
            .any(|w| w.case.ends_with("/.moat/canaries.json") && w.before == Verdict::Deny),
        "{:#?}",
        back.widenings
    );
}

/// The class #512 belongs to: a change that turns calls the agent's own
/// prompt decided (`defer`) into calls that run unasked (`allow`). Here an
/// allow rule meant for dotfiles covers the whole home directory: reading a
/// document, or the SSH key through a glob the classifier cannot expand
/// (`cat ~/.s[[:alpha:]]h/id_rsa`, deferred to the agent's prompt), now runs
/// unasked.
#[test]
fn a_defer_to_allow_change_is_reported_case_by_case() {
    let mut new = default();
    new.allow.push(RuleGroup {
        id: "dotfiles".into(),
        fs_read: vec!["~/**".into()],
        ..RuleGroup::default()
    });
    // The secret-exfiltration fixtures (T1), in both contexts: every fixture
    // is decided in the upgrade test above.
    let t1: Vec<Probe> = corpus()
        .into_iter()
        .filter(|p| matches!(&p.source, WideningSource::Fixture(id) if id.starts_with("T1-")))
        .collect();
    let report = widen::compare(&default(), &new, &contexts(), &t1).unwrap();
    assert!(report.widens());
    assert!(
        report.widenings.iter().all(|w| w.before != Verdict::Deny),
        "a deny rule still wins: {:#?}",
        report.widenings
    );
    // The bypass this class opens: a key read through a glob the classifier
    // cannot expand was left to the agent's prompt; it now runs unasked.
    let key = report
        .widenings
        .iter()
        .find(|w| w.source == WideningSource::Fixture("T1-glob-posix-class-reads-ssh-key".into()))
        .unwrap_or_else(|| panic!("{:#?}", report.widenings));
    assert_eq!(
        (key.before, key.after),
        (Verdict::Defer, Verdict::Allow),
        "{key:?}"
    );
    assert!(key.after_rules.iter().any(|r| r == "dotfiles"), "{key:?}");
    let proven = report
        .proof
        .iter()
        .find(|p| p.kind == "fs.read" && p.context == 0)
        .unwrap();
    assert_eq!(proven.outcome, Outcome::Widens);
    assert!(
        report
            .widenings
            .iter()
            .any(|w| matches!(w.source, WideningSource::Fixture(_))),
        "a conformance fixture shows it too: {:#?}",
        report.widenings
    );
    assert!(
        report
            .widenings
            .iter()
            .any(|w| w.case.starts_with("read /Users/me/") && w.before == Verdict::Defer),
        "{:#?}",
        report.widenings
    );
}

#[test]
fn a_pure_narrowing_passes() {
    let mut new = default();
    new.deny.push(RuleGroup {
        id: "no-tax-records".into(),
        fs_read: vec!["~/Documents/tax/**".into()],
        net: vec!["*.tax.example".into()],
        ..RuleGroup::default()
    });
    let report = compare_rules(&default(), &new);
    assert!(!report.widens(), "{:#?}", report.widenings);
    assert_eq!(report.rules.len(), 1);
}
