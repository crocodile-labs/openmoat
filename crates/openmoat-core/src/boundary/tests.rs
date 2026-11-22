use super::*;

/// A Linux Lightweight run without bubblewrap, as planned before the start.
fn port_only() -> EffectiveBoundary {
    use Mechanism::*;
    EffectiveBoundary {
        version: VERSION,
        os: "linux".to_owned(),
        requested: Requested::Default,
        tier: Tier::Lightweight,
        downgrades: vec![
            Downgrade {
                what: Weaker::Tier,
                chosen: false,
                why: "bubblewrap is not installed".to_owned(),
            },
            Downgrade {
                what: Weaker::Network,
                chosen: false,
                why: "bubblewrap is not installed".to_owned(),
            },
        ],
        network: Network {
            mode: NetworkMode::PortOnly,
            proxy_port: Some(41_000),
        },
        landlock: Some(Landlock {
            abi: Some(4),
            unavailable: None,
            enforcement: None,
        }),
        tool_token: ToolToken::Withheld,
        restrictions: vec![
            Restriction::planned(LandlockFilesystem, true, true),
            Restriction::planned(LandlockTcpPort, true, true),
            Restriction::planned(LandlockScopes, false, true),
            Restriction::planned(LandlockResolveUnix, false, true),
            Restriction::planned(LandlockUdp, false, true),
            Restriction::planned(Seccomp, true, true),
            Restriction::planned(NoNewPrivs, true, true),
            Restriction::planned(NetworkNamespace, false, false),
            Restriction::planned(IsolatedView, false, false),
        ],
        launch: None,
        environment: None,
        score: None,
    }
}

fn verified(abi: u32) -> LaunchCheck {
    LaunchCheck {
        landlock_abi: Some(abi),
        landlock: Some(Enforcement::Partial),
        no_new_privs_set: Some(true),
        seccomp_filters: Some(2),
        inherited_seccomp_filters: Some(0),
        proc_seccomp_filters: Some(2),
        proc_no_new_privs: Some(true),
        proc_seccomp_filter: Some(true),
        in_bubblewrap: false,
        failure: None,
    }
}

#[test]
fn a_planned_record_has_nothing_applied_or_tested() {
    let planned = port_only();
    assert!(planned.downgraded());
    assert!(
        planned
            .restrictions
            .iter()
            .all(|r| r.applied.is_none() && r.tested.is_none())
    );
    assert_eq!(planned.missing(), Vec::<String>::new());
}

/// The launch replaces the probe's ABI with `restrict_self`'s, marks what
/// applied, and what `/proc` confirmed; best-effort steps the kernel lacks
/// are not applied and not missing.
#[test]
fn a_verified_launch_fills_applied_and_tested() {
    let mut record = port_only();
    record.launched(verified(5));
    let landlock = record.landlock.as_ref().unwrap();
    assert_eq!(landlock.abi, Some(5));
    assert_eq!(landlock.enforcement, Some(Enforcement::Partial));
    let get = |m| record.restriction(m).unwrap().clone();
    assert_eq!(get(Mechanism::LandlockFilesystem).applied, Some(true));
    assert_eq!(get(Mechanism::LandlockFilesystem).tested, None);
    // ABI 5 has neither best-effort step: not applied, whatever the ruleset says.
    assert_eq!(get(Mechanism::LandlockScopes).applied, Some(false));
    assert_eq!(get(Mechanism::LandlockResolveUnix).applied, Some(false));
    assert_eq!(get(Mechanism::Seccomp).applied, Some(true));
    assert_eq!(get(Mechanism::Seccomp).tested, Some(true));
    assert_eq!(get(Mechanism::NoNewPrivs).tested, Some(true));
    // Not configured: left as planned.
    assert_eq!(get(Mechanism::NetworkNamespace).applied, None);
    assert!(record.missing().is_empty(), "{:?}", record.missing());
    let gaps = record.launch.as_ref().unwrap().linux_gaps();
    assert_eq!(gaps, Vec::<&str>::new());
}

#[test]
fn a_kernel_with_abi_9_applies_every_step() {
    let mut record = port_only();
    for r in &mut record.restrictions {
        r.available |= matches!(
            r.name,
            Mechanism::LandlockScopes | Mechanism::LandlockResolveUnix
        );
    }
    let mut check = verified(9);
    check.landlock = Some(Enforcement::Full);
    record.launched(check);
    let get = |m| record.restriction(m).unwrap().applied;
    assert_eq!(get(Mechanism::LandlockScopes), Some(true));
    assert_eq!(get(Mechanism::LandlockResolveUnix), Some(true));
}

/// A partly enforced ruleset on a kernel that has a step: whether that step
/// applied is unknown; a step past the kernel's ABI is still not applied.
#[test]
fn a_partial_ruleset_leaves_a_step_the_kernel_has_unknown() {
    let mut record = port_only();
    record.launched(verified(8));
    let get = |m| record.restriction(m).unwrap().applied;
    assert_eq!(get(Mechanism::LandlockScopes), None);
    assert_eq!(get(Mechanism::LandlockResolveUnix), Some(false));
}

/// What the tier promises and `/proc` did not show is missing, by name.
#[test]
fn a_missing_seccomp_filter_or_no_new_privs_is_named() {
    let mut check = verified(6);
    check.proc_seccomp_filter = Some(false);
    check.proc_no_new_privs = None;
    let gaps = check.linux_gaps();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    assert!(gaps[0].contains("NoNewPrivs: 1"), "{gaps:?}");
    assert!(gaps[1].contains("Seccomp: 2"), "{gaps:?}");
    check.failure = Some(gaps.join("; "));
    let mut record = port_only();
    record.launched(check);
    let missing = record.missing();
    assert!(missing.contains(&"seccomp".to_owned()), "{missing:?}");
    assert!(
        missing.iter().any(|m| m.contains("Seccomp: 2")),
        "{missing:?}"
    );
}

#[test]
fn an_unenforced_ruleset_is_a_gap() {
    let mut check = verified(4);
    check.landlock = Some(Enforcement::None);
    assert_eq!(check.linux_gaps(), ["the Landlock rules are not enforced"]);
    let mut record = port_only();
    record.launched(check);
    let missing = record.missing();
    assert!(
        missing.contains(&"landlock_filesystem".to_owned()),
        "{missing:?}"
    );
}

/// The JSON form scripts read: snake-case names, the downgrade and its
/// reason, and a round trip.
#[test]
fn the_json_form_names_the_tier_and_the_downgrade() {
    let record = port_only();
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["requested"], "default");
    assert_eq!(json["tier"], "lightweight");
    assert_eq!(json["network"]["mode"], "port_only");
    assert_eq!(json["downgrades"][0]["what"], "tier");
    assert_eq!(json["downgrades"][0]["why"], "bubblewrap is not installed");
    assert_eq!(json["tool_token"]["state"], "withheld");
    assert_eq!(json["restrictions"][0]["name"], "landlock_filesystem");
    assert!(json["restrictions"][0]["applied"].is_null());
    let back: EffectiveBoundary = serde_json::from_value(json).unwrap();
    assert_eq!(back, record);
    let kept = serde_json::to_value(ToolToken::NotWithheld("no wrapper".into())).unwrap();
    assert_eq!(kept["state"], "not_withheld");
    assert_eq!(kept["why"], "no wrapper");
}

/// A record written before the environment part existed still reads, and
/// one with it keeps names only through a round trip.
#[test]
fn the_environment_part_is_optional_and_round_trips() {
    let mut json = serde_json::to_value(port_only()).unwrap();
    assert!(json.get("environment").is_none(), "{json}");
    json.as_object_mut().unwrap().remove("environment");
    let old: EffectiveBoundary = serde_json::from_value(json).unwrap();
    assert_eq!(old.environment, None);
    let mut record = port_only();
    record.environment = Some(RunEnvironment {
        scrubbed: true,
        why: "`sandbox.env: scrubbed` in your policy".to_owned(),
        passed: vec!["HOME".to_owned(), "PATH".to_owned()],
        withheld: vec!["AWS_SECRET_ACCESS_KEY".to_owned()],
        brokered: vec!["GITHUB_TOKEN".to_owned()],
    });
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["environment"]["scrubbed"], true);
    assert_eq!(json["environment"]["withheld"][0], "AWS_SECRET_ACCESS_KEY");
    let back: EffectiveBoundary = serde_json::from_value(json).unwrap();
    assert_eq!(back, record);
}

#[test]
fn every_mechanism_id_matches_its_json_name() {
    use Mechanism::*;
    for m in [
        Seatbelt,
        LandlockFilesystem,
        LandlockTcpPort,
        LandlockScopes,
        LandlockResolveUnix,
        LandlockUdp,
        Seccomp,
        NoNewPrivs,
        NetworkNamespace,
        IsolatedView,
    ] {
        assert_eq!(serde_json::to_value(m).unwrap(), m.id());
    }
}

/// A report with nothing in it is not a verified start: every restriction
/// the tier promises and nothing confirmed counts as missing, and the gaps
/// are found here even when the reporter named none.
#[test]
fn an_empty_report_is_missing_everything_the_tier_promised() {
    let check = LaunchCheck::default();
    let failure = check.linux_failure().unwrap();
    assert!(failure.contains("not enforced"), "{failure}");
    assert!(failure.contains("NoNewPrivs: 1"), "{failure}");
    let mut record = port_only();
    record.launched(check);
    let missing = record.missing();
    for name in [
        "landlock_filesystem",
        "landlock_tcp_port",
        "seccomp",
        "no_new_privs",
    ] {
        assert!(missing.contains(&name.to_owned()), "{name}: {missing:?}");
    }
    // Best-effort steps the kernel lacks are never missing.
    assert!(
        !missing.contains(&"landlock_scopes".to_owned()),
        "{missing:?}"
    );
    // A reporter's own failure is kept as it said it.
    let named = LaunchCheck {
        failure: Some("stopped inside".to_owned()),
        ..LaunchCheck::default()
    };
    assert_eq!(named.linux_failure().as_deref(), Some("stopped inside"));
    assert_eq!(verified(6).linux_failure(), None);
}

/// Before a start (the plan) nothing unknown is missing.
#[test]
fn unknown_is_missing_only_after_the_start() {
    let planned = Restriction::planned(Mechanism::Seccomp, true, true);
    assert!(!planned.missing(false));
    assert!(planned.missing(true));
    let off = Restriction::planned(Mechanism::NetworkNamespace, false, false);
    assert!(!off.missing(true));
}

/// Each platform's weights add up to 100, and no mechanism is weighted twice.
#[test]
fn every_platforms_weights_add_up_to_100() {
    for os in ["linux", "macos"] {
        let table = weights(os);
        assert_eq!(table.iter().map(|(_, w)| w).sum::<u32>(), 100, "{os}");
        for (i, (m, _)) in table.iter().enumerate() {
            assert!(table[i + 1..].iter().all(|(n, _)| n != m), "{os}: {m:?}");
        }
    }
    assert_eq!(weights("windows"), []);
}

/// The port-only plan on ABI 4: files, the TCP port, seccomp and
/// `no_new_privs` in force; every newer step, the namespace and the view
/// missing, each named with what brings it.
#[test]
fn a_port_only_plan_on_abi_4_scores_55_and_names_what_is_missing() {
    let mut record = port_only();
    record.rescore();
    let score = record.score.clone().unwrap();
    assert_eq!(score.points, 55, "{score:?}");
    assert!(!score.complete());
    let line = score.line();
    for expected in [
        "55/100",
        "landlock_udp (not on this system: needs Landlock ABI 10, Linux 7.2",
        "landlock_scopes (not on this system: needs Landlock ABI 6",
        "network_namespace (not on this system: needs bubblewrap",
        "isolated_view (not on this system: needs the Isolated tier",
    ] {
        assert!(line.contains(expected), "{expected}: {line}");
    }
    assert!(!line.contains("landlock_filesystem"), "{line}");
}

/// Every feature in force, confirmed after the start: 100, complete.
#[test]
fn a_full_isolated_run_on_abi_10_scores_100() {
    let mut record = port_only();
    for r in &mut record.restrictions {
        r.available = true;
        r.configured = true;
    }
    let mut check = verified(10);
    check.landlock = Some(Enforcement::Full);
    check.in_bubblewrap = true;
    record.launched(check);
    let score = record.score.clone().unwrap();
    assert_eq!(score.points, 100, "{:?}", score.missing());
    assert!(score.complete());
    assert!(
        score.line().contains("every kernel feature"),
        "{}",
        score.line()
    );
}

/// After the start, a best-effort step that cannot be confirmed (a partly
/// enforced ruleset) is not in force for the score, so strict refuses it,
/// while `missing()` (which stops every run) still lets it pass.
#[test]
fn an_unconfirmed_step_after_the_start_is_not_in_force() {
    let mut record = port_only();
    for r in &mut record.restrictions {
        r.available |= r.name == Mechanism::LandlockScopes;
    }
    record.launched(verified(8));
    assert!(record.missing().is_empty(), "{:?}", record.missing());
    let score = record.score.clone().unwrap();
    let scopes = score
        .items
        .iter()
        .find(|i| i.name == Mechanism::LandlockScopes)
        .unwrap();
    assert!(!scopes.in_force);
    assert_eq!(
        scopes.missing.as_deref(),
        Some("not confirmed in force after the start")
    );
}

/// A failed start scores only what was never part of the plan as missing
/// for its own reason; everything else is missing because the start failed.
#[test]
fn a_failed_start_has_nothing_in_force() {
    let mut record = port_only();
    record.launched(LaunchCheck {
        failure: Some("stopped".to_owned()),
        ..LaunchCheck::default()
    });
    assert_eq!(record.score.unwrap().points, 0);
}

/// A platform without a sandbox scores 0 and is never complete.
#[test]
fn no_sandbox_scores_0() {
    let mut record = port_only();
    record.os = "windows".to_owned();
    record.rescore();
    let score = record.score.unwrap();
    assert_eq!(score.points, 0);
    assert!(!score.complete());
    assert!(score.line().contains("no sandbox"), "{}", score.line());
}

/// The score is part of the JSON form, and a record without one still reads.
#[test]
fn the_score_round_trips_and_is_optional() {
    let mut record = port_only();
    record.rescore();
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["score"]["points"], 55);
    assert_eq!(json["score"]["items"][0]["name"], "landlock_filesystem");
    let back: EffectiveBoundary = serde_json::from_value(json).unwrap();
    assert_eq!(back, record);
    let old = serde_json::to_value(port_only()).unwrap();
    assert!(old.get("score").is_none(), "{old}");
}
