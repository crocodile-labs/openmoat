use openmoat_audit::Store;
use openmoat_core::boundary::{Enforcement, Mechanism, Tier as Applied};

use super::*;
use crate::taint::run::LINK_HOST;

fn planned(asked: Asked, tier: &Tier, port_only: Option<&str>) -> EffectiveBoundary {
    plan(Plan {
        asked,
        tier,
        port_only: port_only.map(str::to_owned),
        kernel: Some(&Kernel::Abi(5)),
        token: ToolToken::Withheld,
        port: Some(41_000),
        project_top_open: false,
    })
}

/// No bubblewrap: the tier and the network are both downgrades, forced, and
/// say why; the record names the asked and the applied tier.
#[test]
fn a_forced_fallback_is_two_downgrades() {
    let why = "bubblewrap is not installed";
    let tier = Tier::Lightweight(Lightweight::Unavailable(why.to_owned()));
    let record = planned(Asked::Default, &tier, Some(why));
    assert_eq!(record.requested, Requested::Default);
    assert_eq!(record.tier, Applied::Lightweight);
    assert_eq!(record.network.mode, NetworkMode::PortOnly);
    assert_eq!(record.downgrades.len(), 2, "{:?}", record.downgrades);
    assert!(record.downgrades.iter().all(|d| !d.chosen && d.why == why));
    assert_eq!(record.landlock.as_ref().unwrap().abi, Some(5));
    assert!(record.launch.is_none());
}

#[test]
fn no_isolate_is_a_chosen_downgrade_and_isolated_is_none() {
    let record = planned(
        Asked::NoIsolate,
        &Tier::Lightweight(Lightweight::OptedOut),
        None,
    );
    assert_eq!(record.requested, Requested::Lightweight);
    assert_eq!(record.downgrades.len(), 1);
    assert!(record.downgrades[0].chosen);
    assert_eq!(record.network.mode, platform::NETWORK);
    let record = planned(Asked::Default, &Tier::Isolated { asked: false }, None);
    assert_eq!(record.tier, Applied::Isolated);
    assert!(!record.downgraded());
    // The platform's tier without a choice (macOS) is no downgrade either.
    let record = planned(
        Asked::Default,
        &Tier::Lightweight(Lightweight::Platform),
        None,
    );
    assert!(!record.downgraded());
}

/// `sandbox.project_top: writable` in force is the person's own downgrade,
/// beside the forced ones, and its JSON names it (ADR-090).
#[test]
fn an_open_project_top_is_a_chosen_downgrade() {
    let why = "bubblewrap is not installed";
    let tier = Tier::Lightweight(Lightweight::Unavailable(why.to_owned()));
    let record = plan(Plan {
        asked: Asked::Default,
        tier: &tier,
        port_only: Some(why.to_owned()),
        kernel: Some(&Kernel::Abi(5)),
        token: ToolToken::Withheld,
        port: None,
        project_top_open: true,
    });
    assert_eq!(record.downgrades.len(), 3, "{:?}", record.downgrades);
    let top = &record.downgrades[2];
    assert_eq!(top.what, Weaker::ProjectTop);
    assert!(top.chosen);
    assert!(
        top.why.contains("sandbox.project_top: writable"),
        "{}",
        top.why
    );
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["downgrades"][2]["what"], "project_top");
    let shown = render::boundary::lines(&record).join("\n");
    assert!(shown.contains("downgrade (project top, chosen)"), "{shown}");
    // Not in force: no such downgrade.
    let closed = planned(Asked::Default, &tier, Some(why));
    assert!(
        closed
            .downgrades
            .iter()
            .all(|d| d.what != Weaker::ProjectTop)
    );
}

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    drop(Store::open(&home.audit_path()).unwrap());
    (dir, home)
}

/// One row in the run's session with the whole record as its reason; a
/// launch that found a gap is a `deny` row and stops the run.
#[test]
fn the_row_holds_the_record_and_a_gap_refuses() {
    assert!(TOOL.parse::<openmoat_hosts::Host>().is_err());
    let (_dir, home) = home();
    let tier = Tier::Isolated { asked: true };
    let mut record = planned(Asked::Isolate, &tier, None);
    launched(&home, ("run-1-abcd", "/p"), &mut record, None).unwrap();
    let mut bad = planned(Asked::Isolate, &tier, None);
    let check = LaunchCheck {
        landlock: Some(Enforcement::Partial),
        no_new_privs_set: Some(true),
        seccomp_filters: Some(2),
        proc_no_new_privs: Some(true),
        proc_seccomp_filter: Some(false),
        failure: Some("the agent's /proc status does not show `Seccomp: 2`".to_owned()),
        ..LaunchCheck::default()
    };
    let refused = launched(&home, ("run-1-abcd", "/p"), &mut bad, Some(check)).unwrap_err();
    let shown = format!("{refused:#}");
    assert!(shown.contains("Seccomp: 2"), "{shown}");
    // Linux plans seccomp, which the check marks missing by name; macOS
    // plans Seatbelt alone.
    if bad.restriction(Mechanism::Seccomp).is_some() {
        assert!(shown.contains("seccomp;"), "{shown}");
    }
    let store = Store::open_read_only(&home.audit_path()).unwrap();
    let rows = store.since(0, Some(LINK_HOST)).unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.tool, TOOL);
        assert_eq!(row.rules, [RULE]);
        assert_eq!(row.session_id, "run-1-abcd");
        let back: EffectiveBoundary = serde_json::from_str(&row.reasons[0]).unwrap();
        assert_eq!(back.tier, Applied::Isolated);
    }
    assert_eq!(rows[0].verdict, Verdict::Allow);
    assert_eq!(rows[1].verdict, Verdict::Deny);
}
