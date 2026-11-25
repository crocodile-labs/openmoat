use super::*;

/// A Windows record with `restrictions`, planned, its network held by the
/// proxy variables (ADR-115).
fn windows(restrictions: Vec<Restriction>) -> EffectiveBoundary {
    let mut record = port_only();
    record.os = "windows".to_owned();
    record.landlock = None;
    record.downgrades.clear();
    record.network.mode = NetworkMode::ProxyVariables;
    record.restrictions = restrictions;
    record.rescore();
    record
}

/// What a run as the agent account reports when every check passed.
fn account_confirmed() -> LaunchCheck {
    LaunchCheck {
        agent_account: Some(true),
        agent_token_account: Some(true),
        job_object: Some(true),
        agent_in_job: Some(true),
        read_denies: Some(true),
        ..LaunchCheck::default()
    }
}

/// A Windows run (ADR-115) with its token and job confirmed scores 55: the
/// network filters and read denial need the agent account, and say so.
#[test]
fn a_confirmed_windows_run_scores_55_and_names_network_and_reads() {
    let mut record = windows(vec![
        Restriction::planned(Mechanism::RestrictedToken, true, true),
        Restriction::planned(Mechanism::JobObject, true, true),
        Restriction::planned(Mechanism::WfpNetwork, false, false),
        Restriction::planned(Mechanism::WindowsReadDeny, false, false),
    ]);
    assert_eq!(record.score.as_ref().unwrap().points, 55);
    record.launched(LaunchCheck {
        restricted_token: Some(true),
        agent_token_restricted: Some(true),
        job_object: Some(true),
        agent_in_job: Some(true),
        ..LaunchCheck::default()
    });
    assert!(record.missing().is_empty(), "{:?}", record.missing());
    let score = record.score.clone().unwrap();
    assert_eq!(score.points, 55, "{score:?}");
    assert!(!score.complete());
    let line = score.line();
    assert!(
        line.contains("wfp_network (not on this system: needs the agent account's network filters"),
        "{line}"
    );
    assert!(
        line.contains("windows_read_deny (not on this system: needs the agent account"),
        "{line}"
    );
    assert!(line.contains("openmoat agent-account setup"), "{line}");

    // A token the agent's own process does not show is missing: the run stops.
    record.launched(LaunchCheck {
        restricted_token: Some(true),
        agent_token_restricted: Some(false),
        job_object: Some(true),
        agent_in_job: Some(true),
        ..LaunchCheck::default()
    });
    assert_eq!(record.missing(), ["restricted_token"]);
    assert_eq!(record.score.unwrap().points, 10);
}

/// A run as the agent account without its network filters (a setup of
/// ADR-129's first step): the account stands in for the token in the score,
/// the read denies count once the agent's token shows the account, and the
/// filters are named with what adds them: 70.
#[test]
fn a_confirmed_account_run_scores_70_and_counts_reads_only_when_confirmed() {
    let mut record = windows(vec![
        Restriction::planned(Mechanism::AgentAccount, true, true),
        Restriction::planned(Mechanism::JobObject, true, true),
        Restriction::planned(Mechanism::WfpNetwork, false, false),
        Restriction::planned(Mechanism::WindowsReadDeny, true, true),
    ]);
    let planned = record.score.clone().unwrap();
    assert_eq!(planned.points, 70, "{planned:?}");
    assert_eq!(planned.items[0].name, Mechanism::AgentAccount);
    record.launched(account_confirmed());
    assert!(record.missing().is_empty(), "{:?}", record.missing());
    let score = record.score.clone().unwrap();
    assert_eq!(score.points, 70, "{score:?}");
    assert!(
        score
            .line()
            .contains("wfp_network (not on this system: needs the agent account's network filters")
    );

    // A token whose user is not the account: neither writes nor reads count,
    // and the run stops.
    record.launched(LaunchCheck {
        agent_token_account: Some(false),
        ..account_confirmed()
    });
    assert_eq!(record.missing(), ["agent_account", "windows_read_deny"]);
    assert_eq!(record.score.clone().unwrap().points, 10);

    // Nothing read back is not confirmation either.
    record.launched(LaunchCheck {
        agent_token_account: None,
        ..account_confirmed()
    });
    assert_eq!(record.missing(), ["agent_account", "windows_read_deny"]);
}

/// A run as the agent account with its network filters confirmed (ADR-129's
/// second step) scores 100 and is complete, so `sandbox.strict: true` takes
/// it; the name lookups that leave through the system's resolver are the
/// record's named `dns` downgrade, not points. The filters count only once
/// they were read back and the agent's token shows the account.
#[test]
fn a_filtered_account_run_scores_100_with_its_dns_downgrade_named() {
    let mut record = windows(vec![
        Restriction::planned(Mechanism::AgentAccount, true, true),
        Restriction::planned(Mechanism::JobObject, true, true),
        Restriction::planned(Mechanism::WfpNetwork, true, true),
        Restriction::planned(Mechanism::WindowsReadDeny, true, true),
    ]);
    record.network.mode = NetworkMode::WfpAccount;
    record.downgrades.push(Downgrade {
        what: Weaker::Dns,
        chosen: false,
        why: "name lookups go through the DNS Client service".to_owned(),
    });
    record.rescore();
    assert_eq!(record.score.as_ref().unwrap().points, 100);
    let filtered = LaunchCheck {
        wfp_filters: Some(true),
        ..account_confirmed()
    };
    record.launched(filtered.clone());
    assert!(record.missing().is_empty(), "{:?}", record.missing());
    let score = record.score.clone().unwrap();
    assert_eq!(score.points, 100, "{score:?}");
    assert!(score.complete());
    assert!(record.downgraded());
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["network"]["mode"], "wfp_account");
    assert_eq!(json["downgrades"][0]["what"], "dns");
    assert_eq!(json["launch"]["wfp_filters"], true);

    // Filters not confirmed before the start are missing: the run stops, and
    // they are not in the score.
    record.launched(LaunchCheck {
        wfp_filters: None,
        ..filtered.clone()
    });
    assert_eq!(record.missing(), ["wfp_network"]);
    assert_eq!(record.score.clone().unwrap().points, 70);

    // Filters name the account: a token of another user holds nothing.
    record.launched(LaunchCheck {
        agent_token_account: Some(false),
        ..filtered
    });
    assert_eq!(
        record.missing(),
        ["agent_account", "wfp_network", "windows_read_deny"]
    );
    assert_eq!(record.score.unwrap().points, 10);
}
