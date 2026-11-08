use std::collections::BTreeSet;

use openmoat_hosts::Host;

use super::os::Probe;
use super::status::{Evidence, Layer, Status};
use super::{Checked, PROMISES, scenario_rows, with_profile};
use crate::commands::bench::scenario::scenarios;

fn unexercised(why: &str) -> Evidence {
    Evidence::Unexercised(why.to_owned())
}

#[test]
fn no_evidence_is_not_tested_never_a_pass() {
    assert_eq!(
        Status::of([], "nothing ran"),
        Status::NotTested("nothing ran".into())
    );
}

#[test]
fn a_pass_needs_every_piece_of_evidence_held() {
    assert_eq!(
        Status::of([Evidence::Held, Evidence::Held], ""),
        Status::Pass
    );
    // One run that could not happen keeps the layer from passing.
    assert_eq!(
        Status::of([Evidence::Held, unexercised("no sandbox")], ""),
        Status::NotTested("no sandbox".into())
    );
    assert_eq!(
        Status::of([unexercised("a"), unexercised("a"), unexercised("b")], ""),
        Status::NotTested("a; b".into())
    );
}

#[test]
fn a_broken_run_fails_the_layer_whatever_else_ran() {
    let status = Status::of(
        [
            Evidence::Held,
            unexercised("no sandbox"),
            Evidence::Broken("read went through".into()),
        ],
        "",
    );
    assert_eq!(status, Status::Fail("read went through".into()));
    assert_eq!(status.word(), "FAIL");
}

#[test]
fn the_profile_check_only_annotates_a_row_that_did_not_run() {
    let not_run = Status::NotTested("sandbox did not start".into());
    for denies in [Some(true), Some(false), None] {
        let status = with_profile(not_run.clone(), denies);
        assert!(matches!(status, Status::NotTested(_)), "{status:?}");
    }
    assert_eq!(
        with_profile(not_run, Some(true)).reason(),
        Some("sandbox did not start (the policy's OS rules for this session deny it; not run)")
    );
    assert_eq!(with_profile(Status::Pass, Some(false)), Status::Pass);
    let fail = Status::Fail("x".into());
    assert_eq!(with_profile(fail.clone(), Some(true)), fail);
}

#[test]
fn statuses_serialise_with_their_reason() {
    let json = |s: &Status| serde_json::to_value(s).unwrap();
    assert_eq!(json(&Status::Pass), serde_json::json!({"status": "pass"}));
    assert_eq!(
        json(&Status::NotTested("why".into())),
        serde_json::json!({"status": "not-tested-here", "reason": "why"})
    );
    assert_eq!(
        json(&Status::Fail("why".into())),
        serde_json::json!({"status": "fail", "reason": "why"})
    );
    assert_eq!(
        serde_json::to_value(Layer::OsSandbox).unwrap(),
        serde_json::json!("os-sandbox")
    );
}

#[test]
fn every_promise_names_bundled_scenarios_and_a_layer() {
    let bundled: BTreeSet<String> = scenarios()
        .unwrap()
        .into_iter()
        .map(|(_, s)| s.id)
        .collect();
    let mut ids = BTreeSet::new();
    for promise in &PROMISES {
        assert!(ids.insert(promise.id), "duplicate promise {}", promise.id);
        assert!(promise.question.ends_with('?'), "{}", promise.id);
        for id in promise.scenarios {
            assert!(bundled.contains(*id), "{}: no scenario {id}", promise.id);
        }
        let layers = !promise.scenarios.is_empty()
            || promise.os.is_some()
            || promise.network
            || promise.fails_closed;
        assert!(layers, "{}: no layer checks it", promise.id);
        assert!(
            promise.scenarios.is_empty() == promise.hook_check.is_empty(),
            "{}: scenarios and hook_check go together",
            promise.id
        );
    }
}

#[test]
fn os_probes_go_for_their_file_and_say_how_to_rerun_them() {
    for probe in [
        Probe::ReadSshKey,
        Probe::BuildScriptReadsAgentLogin,
        Probe::WritePolicy,
    ] {
        assert!(probe.check().contains(&probe.command()), "{probe:?}");
        assert!(probe.id().starts_with("os-"));
    }
    assert!(Probe::ReadSshKey.command().contains(".ssh/id_rsa"));
    assert!(Probe::WritePolicy.command().contains(">>"));
}

fn checked(scenario: &str, policy: &[&str], hook: &[&str]) -> Checked {
    Checked {
        scenario: scenario.to_owned(),
        host: Host::ClaudeCode,
        policy: policy.iter().map(|s| (*s).to_owned()).collect(),
        hook: hook.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn policy_and_hook_rows_are_judged_apart() {
    let promise = &PROMISES[0];
    let id = promise.scenarios[0];
    let rows = scenario_rows(promise, &[checked(id, &[], &["host reads allow"])]);
    let by = |layer| rows.iter().find(|r| r.layer == layer).unwrap();
    assert_eq!(by(Layer::Policy).status, Status::Pass);
    assert!(
        matches!(&by(Layer::Hook).status, Status::Fail(why) if why.contains("host reads allow"))
    );
    let rows = scenario_rows(promise, &[checked(id, &["expected deny, got allow"], &[])]);
    assert!(matches!(rows[0].status, Status::Fail(_)));
    assert_eq!(rows[1].status, Status::Pass);
}

#[test]
fn a_promise_with_no_run_on_the_chosen_hosts_is_not_tested() {
    let rows = scenario_rows(&PROMISES[0], &[checked("unrelated", &[], &[])]);
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| matches!(r.status, Status::NotTested(_)))
    );
}

#[test]
fn markdown_cells_cannot_break_the_table() {
    assert_eq!(super::render::cell("a | b\nc"), "a \\| b c");
}

#[test]
fn os_release_names_the_distribution() {
    let text = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
    assert_eq!(
        crate::os_version::pretty_name(text).as_deref(),
        Some("Ubuntu 24.04.1 LTS")
    );
    assert_eq!(crate::os_version::pretty_name("ID=x\n"), None);
}
