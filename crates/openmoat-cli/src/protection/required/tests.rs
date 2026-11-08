use openmoat_core::{Policy, RequiredBy, RequiredLevel, Verdict};
use openmoat_hosts::Host;

use super::*;

/// A host OpenMoat writes no OS sandbox for, on every OS.
fn hook_only_host() -> Host {
    Host::ALL
        .into_iter()
        .find(|h| h.spec().sandbox.is_none())
        .unwrap()
}

#[test]
fn levels_meet_what_they_include() {
    use RequiredLevel::{HookAndOsSandbox, HookOnly};
    assert!(Level::HookAndOsSandbox.meets(HookAndOsSandbox));
    assert!(Level::HookAndOsSandbox.meets(HookOnly));
    assert!(Level::HookOnly.meets(HookOnly));
    assert!(!Level::HookOnly.meets(HookAndOsSandbox));
    for none in [Level::NotProtected, Level::NotSetUp, Level::NotFound] {
        assert!(!none.meets(HookOnly), "{none:?}");
        assert!(!none.meets(HookAndOsSandbox), "{none:?}");
    }
    assert_eq!(level_of(HookOnly), Level::HookOnly);
    assert_eq!(level_of(HookAndOsSandbox), Level::HookAndOsSandbox);
}

#[test]
fn nothing_required_reads_no_level_and_keeps_the_decision() {
    let policy = Policy::parse("version: 1\n").unwrap();
    let got = unmet(&policy, hook_only_host(), || {
        panic!("the level is read only when a level is required")
    });
    assert_eq!(got, None);
}

#[test]
fn below_the_level_is_a_deny_that_names_what_is_missing_and_the_fix() {
    let host = hook_only_host();
    let policy =
        Policy::parse("version: 1\nrequire:\n  protection: hook-and-os-sandbox\n").unwrap();
    let d = unmet(&policy, host, || Level::HookOnly).unwrap();
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, [RULE]);
    let reason = &d.reasons[0];
    for part in [
        "your policy requires hook + OS sandbox for ",
        host.display_name(),
        "this call has hook only: ",
        "to meet it, ",
    ] {
        assert!(reason.contains(part), "{part:?} in {reason}");
    }
    // The hook alone meets a `hook-only` requirement.
    let policy = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
    assert_eq!(unmet(&policy, host, || Level::HookOnly), None);
    // and the sandbox meets both
    let policy =
        Policy::parse("version: 1\nrequire:\n  protection: hook-and-os-sandbox\n").unwrap();
    assert_eq!(unmet(&policy, host, || Level::HookAndOsSandbox), None);
}

#[test]
fn an_agents_own_level_is_the_one_its_calls_are_held_to() {
    let host = hook_only_host();
    let yaml = format!(
        "version: 1\nrequire:\n  protection: hook-and-os-sandbox\n  agents:\n    {}: hook-only\n",
        host.id()
    );
    let policy = Policy::parse(&yaml).unwrap();
    assert_eq!(unmet(&policy, host, || Level::HookOnly), None);
    let other = Host::ALL.into_iter().find(|h| *h != host).unwrap();
    assert!(unmet(&policy, other, || Level::HookOnly).is_some());
}

#[test]
fn the_fix_fits_why_the_sandbox_is_missing() {
    let host = hook_only_host();
    let (what, fix) = missing(host, Level::HookOnly, RequiredLevel::HookAndOsSandbox).unwrap();
    assert!(what.contains(host.display_name()), "{what}");
    match crate::commands::run_unavailable() {
        None => assert!(fix.contains("openmoat run"), "{fix}"),
        Some(_) => assert!(fix.contains("openmoat edit"), "{fix}"),
    }
    if let Some(sandboxed) = Host::ALL
        .into_iter()
        .find(|h| super::super::writes_sandbox(*h))
    {
        let (_, fix) =
            missing(sandboxed, Level::HookOnly, RequiredLevel::HookAndOsSandbox).unwrap();
        assert_eq!(fix, "run `openmoat sandbox sync` in your terminal");
    }
    let (_, fix) = missing(host, Level::NotSetUp, RequiredLevel::HookOnly).unwrap();
    assert_eq!(fix, format!("run `openmoat init --hosts {}`", host.id()));
    assert_eq!(
        missing(host, Level::HookOnly, RequiredLevel::HookOnly),
        None
    );
}

#[test]
fn the_shown_requirement_names_its_source() {
    let host = hook_only_host();
    let requirement = Requirement {
        level: RequiredLevel::HookAndOsSandbox,
        by: RequiredBy::Pack("team".into()),
    };
    let shown = Required::of(host, Level::HookOnly, &requirement);
    assert!(!shown.met);
    assert_eq!(shown.by, "the policy pack `team`");
    assert_eq!(shown.label(), "hook + OS sandbox");
    assert!(shown.missing.is_some() && shown.fix.is_some());
    let met = Required::of(host, Level::HookAndOsSandbox, &requirement);
    assert!(met.met && met.missing.is_none() && met.fix.is_none());
    assert_eq!(by(&RequiredBy::Repository), "the repository policy");
}

/// A typo in an agent id would leave that agent's level out unseen.
#[test]
fn unknown_agent_ids_are_refused() {
    let typo = Policy::parse("version: 1\nrequire:\n  agents:\n    claude: hook-only\n").unwrap();
    let error = check_policy(&typo).unwrap_err().to_string();
    assert!(
        error.contains("`claude` is not an agent OpenMoat knows"),
        "{error}"
    );
    assert!(error.contains("claude-code"), "{error}");
    let known = format!(
        "version: 1\nrequire:\n  agents:\n    {}: hook-only\n",
        hook_only_host().id()
    );
    check_policy(&Policy::parse(&known).unwrap()).unwrap();
    // in a requirement merged in too
    let mut merged = Policy::parse("version: 1\n").unwrap();
    merged.add_requirement(RequiredBy::Repository, typo.require.as_ref().unwrap());
    assert!(check_policy(&merged).is_err());
}

/// Every deny names a step that is not one the block message never suggests.
#[test]
fn the_reason_suggests_no_way_past_the_check() {
    let policy =
        Policy::parse("version: 1\nrequire:\n  protection: hook-and-os-sandbox\n").unwrap();
    for host in Host::ALL {
        for level in [Level::HookOnly, Level::NotProtected, Level::NotSetUp] {
            let Some(d) = unmet(&policy, host, || level) else {
                continue;
            };
            // The agent's name is no suggestion (`encode` is in `OpenCode`).
            let lower = d.reasons[0]
                .replace(host.display_name(), "<agent>")
                .replace(host.id(), "<id>")
                .to_lowercase();
            assert!(!lower.contains("without `openmoat run`"), "{lower}");
            for hint in openmoat_hosts::NEVER_SUGGESTED {
                assert!(!lower.contains(hint), "`{hint}` in {lower}");
            }
        }
    }
}
