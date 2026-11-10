use super::*;
use crate::RepoPolicy;

const USER: &str = "version: 1\nrequire:\n  protection: hook-and-os-sandbox\n  \
    agents:\n    gemini-cli: hook-only\n";

fn level(p: &Policy, host: Option<&str>) -> Option<RequiredLevel> {
    p.required_for(host).map(|r| r.level)
}

#[test]
fn levels_order_from_weakest_to_strongest() {
    assert!(RequiredLevel::HookOnly < RequiredLevel::HookAndOsSandbox);
    assert_eq!(
        RequiredLevel::HookAndOsSandbox.as_str(),
        "hook-and-os-sandbox"
    );
    assert_eq!(RequiredLevel::HookOnly.as_str(), "hook-only");
}

#[test]
fn absent_means_no_requirement() {
    let p = Policy::parse("version: 1\n").unwrap();
    assert_eq!(p.required_for(Some("codex")), None);
    assert_eq!(p.required_for(None), None);
    let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    assert_eq!(p.require, None, "the default policy requires nothing");
    assert_eq!(p.required_for(Some("claude-code")), None);
}

#[test]
fn an_agents_own_level_takes_the_place_of_protection_in_the_same_file() {
    let p = Policy::parse(USER).unwrap();
    assert_eq!(
        level(&p, Some("codex")),
        Some(RequiredLevel::HookAndOsSandbox)
    );
    assert_eq!(level(&p, Some("gemini-cli")), Some(RequiredLevel::HookOnly));
    // A program that is no known agent gets `protection` alone.
    assert_eq!(level(&p, None), Some(RequiredLevel::HookAndOsSandbox));
    assert_eq!(
        p.required_for(Some("codex")).unwrap().by,
        RequiredBy::Policy
    );
}

#[test]
fn bad_levels_ids_and_keys_are_rejected() {
    for bad in [
        "version: 1\nrequire:\n  protection: os-sandbox\n",
        "version: 1\nrequire:\n  protection: none\n",
        "version: 1\nrequire:\n  level: hook-only\n",
        "version: 1\nrequire:\n  agents:\n    Claude Code: hook-only\n",
        "version: 1\nrequire:\n  agents:\n    codex: sandbox\n",
        "version: 1\nrequire: hook-only\n",
    ] {
        assert!(Policy::parse(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn a_repository_raises_the_level_and_never_lowers_it() {
    let user = Policy::parse(USER).unwrap();
    // Every way a repository could try to lower it: a lower level for
    // all agents, for one agent, and for the agent the user lowered.
    for lower in [
        "version: 1\nrequire:\n  protection: hook-only\n",
        "version: 1\nrequire:\n  agents:\n    codex: hook-only\n",
        "version: 1\nrequire: {}\n",
    ] {
        let repo = RepoPolicy::parse(lower).unwrap();
        for trusted in [false, true] {
            let merged = repo.merge(&user, trusted).unwrap();
            assert_eq!(
                merged.required_for(Some("codex")),
                user.required_for(Some("codex")),
                "{lower}"
            );
            assert_eq!(merged.required_for(None), user.required_for(None));
        }
    }
    // Raising: the agent the user lowered, and every agent of a user
    // policy that requires nothing.
    let raise =
        RepoPolicy::parse("version: 1\nrequire:\n  protection: hook-and-os-sandbox\n").unwrap();
    let merged = raise.merge(&user, false).unwrap();
    let gemini = merged.required_for(Some("gemini-cli")).unwrap();
    assert_eq!(gemini.level, RequiredLevel::HookAndOsSandbox);
    assert_eq!(gemini.by, RequiredBy::Repository);
    // An equal level keeps the person's own policy as its source.
    assert_eq!(
        merged.required_for(Some("codex")).unwrap().by,
        RequiredBy::Policy
    );
    let none = Policy::parse("version: 1\n").unwrap();
    let merged = raise.merge_deny(&none).unwrap();
    assert_eq!(
        level(&merged, Some("pi")),
        Some(RequiredLevel::HookAndOsSandbox)
    );
}

#[test]
fn the_strictest_of_every_source_applies() {
    let mut p = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
    let pack = Require {
        protection: None,
        run: None,
        agents: [("codex".to_owned(), RequiredLevel::HookAndOsSandbox)].into(),
    };
    p.add_requirement(RequiredBy::Pack("team".into()), &pack);
    let codex = p.required_for(Some("codex")).unwrap();
    assert_eq!(codex.level, RequiredLevel::HookAndOsSandbox);
    assert_eq!(codex.by, RequiredBy::Pack("team".into()));
    assert_eq!(level(&p, Some("cursor")), Some(RequiredLevel::HookOnly));
}

#[test]
fn the_run_boundary_is_off_unless_a_source_asks_for_it() {
    let plain = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
    assert_eq!(plain.run_boundary_required(), None);
    let none = Policy::parse("version: 1\n").unwrap();
    assert_eq!(none.run_boundary_required(), None);
    let own = Policy::parse("version: 1\nrequire:\n  run: full-boundary\n").unwrap();
    assert_eq!(own.run_boundary_required(), Some(RequiredBy::Policy));
}

#[test]
fn a_repository_can_turn_the_run_boundary_on_and_never_off() {
    let strict = Require {
        run: Some(RunBoundary::FullBoundary),
        ..Require::default()
    };
    let mut p = Policy::parse("version: 1\n").unwrap();
    p.add_requirement(RequiredBy::Repository, &strict);
    assert_eq!(p.run_boundary_required(), Some(RequiredBy::Repository));

    // A later source that says nothing leaves the person's requirement.
    let mut own = Policy::parse("version: 1\nrequire:\n  run: full-boundary\n").unwrap();
    own.add_requirement(RequiredBy::Repository, &Require::default());
    assert_eq!(own.run_boundary_required(), Some(RequiredBy::Policy));
}

#[test]
fn an_unknown_run_boundary_is_an_error() {
    assert!(Policy::parse("version: 1\nrequire:\n  run: mostly\n").is_err());
}
