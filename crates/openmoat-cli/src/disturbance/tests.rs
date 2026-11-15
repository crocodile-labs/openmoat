use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, Decision, Verdict};

use super::*;

const DAY_MS: i64 = 86_400_000;

/// One row of a synthetic log: agent, session, command, verdict, rule,
/// latency in microseconds, time.
type Row<'a> = (&'a str, &'a str, &'a str, Verdict, &'a str, u64, i64);

fn store_with(rows: &[Row<'_>]) -> Store {
    let store = Store::open_in_memory().unwrap();
    for &(host, session, command, verdict, rule, latency_us, ts) in rows {
        let decision = Decision::single(verdict, rule, format!("because {rule}"));
        let action = Action::Shell {
            command: command.to_owned(),
        };
        store
            .record_at(
                &NewEvent {
                    host,
                    session_id: session,
                    call_id: None,
                    cwd: Some("/p"),
                    tool: "Bash",
                    action: Some(&action),
                    decision: &decision,
                    latency_us,
                },
                ts,
            )
            .unwrap();
    }
    store
}

fn agents() -> (Host, Host) {
    (Host::ALL[0], Host::ALL[1])
}

/// Nearest-rank percentiles over 1..=100 ms land on the rank itself; one
/// sample is every percentile; none is no latency at all, not zeros.
#[test]
fn percentiles_are_nearest_rank() {
    let samples: Vec<u64> = (1..=100).rev().map(|ms| ms * 1000).collect();
    let l = Latency::of(samples).unwrap();
    assert_eq!(
        (l.p50, l.p95, l.p99, l.max),
        (50_000, 95_000, 99_000, 100_000)
    );
    let one = Latency::of(vec![7]).unwrap();
    assert_eq!((one.p50, one.p99, one.max), (7, 7, 7));
    let three = Latency::of(vec![30, 10, 20]).unwrap();
    assert_eq!((three.p50, three.p95), (20, 30));
    assert_eq!(Latency::of(Vec::new()), None);
}

#[test]
fn rates_are_per_100_calls_to_two_decimals() {
    assert!((per_100(1, 3) - 33.33).abs() < f64::EPSILON);
    assert!((per_100(2, 3) - 66.67).abs() < f64::EPSILON);
    assert!((per_100(0, 0)).abs() < f64::EPSILON);
    assert!((per_100(5, 5) - 100.0).abs() < f64::EPSILON);
}

/// The synthetic log of the tests below: two agents, a held call allowed
/// later, a person's approval, a kernel error and rows that are no agent's.
fn synthetic() -> Store {
    let (a, b) = agents();
    let (a, b) = (a.id(), b.id());
    store_with(&[
        (a, "s1", "ls", Verdict::Allow, "dev-shell", 1_000, 1_000),
        (
            a,
            "s1",
            "npm i x",
            Verdict::Review,
            "installs",
            3_000,
            2_000,
        ),
        (
            a,
            "s1",
            "npm i x",
            Verdict::Allow,
            APPROVED_SESSION,
            2_000,
            3_000,
        ),
        (
            a,
            "s1",
            "curl x",
            Verdict::Deny,
            "default.net",
            4_000,
            4_000,
        ),
        (a, "s2", "curl x", Verdict::Allow, "dev-shell", 1_000, 5_000),
        (b, "k1", "cat y", Verdict::Defer, "default", 9_000, 6_000),
        (b, "k1", "cat y", Verdict::Deny, KERNEL_ERROR, 20_000, 7_000),
        ("proxy", "p", "GET", Verdict::Allow, "x", 1, 8_000),
        // Outside the window the command reads.
        (a, "s1", "ls", Verdict::Allow, "dev-shell", 1, 2 * DAY_MS),
    ])
}

#[test]
fn figures_split_per_agent_and_add_up_over_all() {
    let (a, b) = agents();
    let events: Vec<_> = synthetic()
        .since(0, None)
        .unwrap()
        .into_iter()
        .filter(|e| e.ts_ms < DAY_MS)
        .collect();
    let d = of(&events, &[(b, 2)]);
    assert_eq!(d.other_rows, 1, "the proxy's row is no agent's call");
    assert_eq!(
        d.agents.iter().map(|g| g.host).collect::<Vec<_>>(),
        [a.id(), b.id()]
    );
    let fa = &d.agents[0].figures;
    assert_eq!(fa.calls, 5);
    assert_eq!(
        (fa.verdicts.allow, fa.verdicts.review, fa.verdicts.deny),
        (3, 1, 1)
    );
    assert_eq!(fa.approved, 1);
    assert_eq!(fa.reviews_later_allowed, 1);
    assert_eq!(
        fa.denies_later_allowed, 0,
        "an allow in another session is another call"
    );
    assert!((fa.per_100_calls.review - 20.0).abs() < f64::EPSILON);
    let fb = &d.agents[1].figures;
    assert_eq!((fb.calls, fb.kernel_errors, fb.guard_timeouts), (2, 1, 2));
    assert_eq!(d.agents[1].hook_failure, HookFailureFacts::of(b));
    let all = &d.overall;
    assert_eq!(all.calls, 7);
    assert_eq!(
        (all.verdicts.defer, all.kernel_errors, all.guard_timeouts),
        (1, 1, 2)
    );
    let latency = all.latency.unwrap();
    assert_eq!(
        (latency.p50, latency.p95, latency.max),
        (3_000, 20_000, 20_000)
    );
}

#[test]
fn a_window_and_an_agent_are_read_from_the_store() {
    let (a, _) = agents();
    let store = synthetic();
    let later = of(&store.since(DAY_MS, None).unwrap(), &[]);
    assert_eq!(later.overall.calls, 1);
    let one = of(&store.since(0, Some(a.id())).unwrap(), &[]);
    assert_eq!(one.agents.len(), 1);
    assert_eq!(one.overall.calls, 6);
}

/// A deny whose same call the same session allows later is counted; the
/// order matters: an allow before it is not "later".
#[test]
fn only_a_later_allow_of_the_same_call_counts() {
    let (a, _) = agents();
    let a = a.id();
    let store = store_with(&[
        (a, "s", "rm x", Verdict::Allow, "r", 1, 1),
        (a, "s", "rm x", Verdict::Deny, "r", 1, 2),
        (a, "s", "curl y", Verdict::Deny, "r", 1, 3),
        (a, "s", "curl y", Verdict::Allow, "r", 1, 4),
    ]);
    let d = of(&store.since(0, None).unwrap(), &[]);
    assert_eq!(d.overall.denies_later_allowed, 1);
}

#[test]
fn an_empty_log_has_no_agents_and_no_latency() {
    let store = Store::open_in_memory().unwrap();
    let d = of(&store.since(0, None).unwrap(), &[]);
    assert_eq!(d.overall, Figures::default());
    assert_eq!(d.agents, Vec::new());
    assert_eq!(d.overall.latency, None);
}

/// The JSON a script reads: its fields and their shapes.
#[test]
fn the_json_shape_is_stable() {
    let (a, _) = agents();
    let store = synthetic();
    let d = of(&store.since(0, Some(a.id())).unwrap(), &[]);
    let json = serde_json::to_value(&d).unwrap();
    let agent = &json["agents"][0];
    for key in [
        "host",
        "name",
        "calls",
        "verdicts",
        "per_100_calls",
        "latency",
        "approved",
        "denies_later_allowed",
        "reviews_later_allowed",
        "kernel_errors",
        "guard_timeouts",
        "hook_failure",
    ] {
        assert!(agent.get(key).is_some(), "{key} missing: {agent:#}");
    }
    for key in ["allow", "defer", "review", "deny"] {
        assert!(agent["verdicts"][key].is_u64(), "{key}");
        assert!(agent["per_100_calls"][key].is_f64(), "{key}");
    }
    for key in ["p50_us", "p95_us", "p99_us", "max_us"] {
        assert!(agent["latency"][key].is_u64(), "{key}");
    }
    for key in ["fails", "times_out"] {
        assert!(agent["hook_failure"][key].is_string(), "{key}");
    }
    assert!(json["overall"]["calls"].is_u64());
    assert!(json["other_rows"].is_u64());
    let empty = serde_json::to_value(of(&[], &[])).unwrap();
    assert!(empty["overall"]["latency"].is_null());
}
