use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, Decision, Verdict};

use super::*;

fn stats(events: &[openmoat_audit::Event]) -> Stats {
    Stats {
        format: FORMAT,
        window: Window {
            since: time::rfc3339(0),
            until: time::rfc3339(86_400_000),
            host: None,
        },
        figures: disturbance::of(events, &[]),
    }
}

#[test]
fn milliseconds_have_one_decimal() {
    assert_eq!(ms(12_345), "12.3");
    assert_eq!(ms(999), "0.9");
    assert_eq!(ms(40_000), "40.0");
}

#[test]
fn an_empty_window_says_so() {
    let out = text(&stats(&[]));
    assert!(out.contains("no agent calls in this window"), "{out}");
}

/// The text names each agent from its spec, gives the table and the spec's
/// hook-failure words; printed so a run shows a sample.
#[test]
fn the_text_has_a_row_per_agent_and_the_spec_facts() {
    let mut store = Store::open_in_memory().unwrap();
    let hosts = [Host::ALL[0], Host::ALL[1]];
    for (i, verdict) in [
        Verdict::Allow,
        Verdict::Allow,
        Verdict::Review,
        Verdict::Defer,
    ]
    .into_iter()
    .enumerate()
    {
        let host = hosts[i % 2];
        let n = u64::try_from(i).unwrap();
        store = store.with_phase_times(&[
            ("stdin", 100 + n),
            ("lock", 2_000 * (n + 1)),
            ("compile", 9_000 + n),
            ("record", 1_500),
        ]);
        let decision = Decision::single(verdict, "r", "because");
        let action = Action::Shell {
            command: format!("echo {i}"),
        };
        let event = NewEvent {
            host: host.id(),
            session_id: "s",
            call_id: None,
            cwd: None,
            tool: "Bash",
            action: Some(&action),
            decision: &decision,
            latency_us: 1_000 * (u64::try_from(i).unwrap() + 1),
        };
        store
            .record_at(&event, 1_000 + i64::try_from(i).unwrap())
            .unwrap();
    }
    let out = text(&stats(&store.since(0, None).unwrap()));
    println!("{out}");
    for host in hosts {
        assert!(out.contains(host.display_name()), "{out}");
        let words = host.spec().hook_failure.fails.words();
        assert!(out.contains(&words), "{out}");
    }
    assert!(out.contains("all agents"), "{out}");
    assert!(out.contains("reviews/100"), "{out}");
    assert!(out.contains("not measured"), "{out}");
    assert!(out.contains("time per guard phase"), "{out}");
    let lock = out
        .lines()
        .find(|l| l.trim_start().starts_with("lock"))
        .unwrap();
    assert_eq!(
        lock.split_whitespace().collect::<Vec<_>>(),
        ["lock", "4", "4.0", "8.0", "8.0"],
        "{out}"
    );
    let order: Vec<&str> = out
        .lines()
        .skip_while(|l| !l.starts_with("time per guard phase"))
        .skip(2)
        .take(4)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(order, ["stdin", "lock", "compile", "record"], "{out}");
}

#[test]
fn rows_without_phase_times_print_no_phase_table() {
    let store = Store::open_in_memory().unwrap();
    let decision = Decision::new(Verdict::Allow);
    let event = NewEvent {
        host: Host::ALL[0].id(),
        session_id: "s",
        call_id: None,
        cwd: None,
        tool: "Bash",
        action: None,
        decision: &decision,
        latency_us: 10,
    };
    store.record_at(&event, 1_000).unwrap();
    let stats = stats(&store.since(0, None).unwrap());
    let out = text(&stats);
    assert!(!out.contains("time per guard phase"), "{out}");
    let json = serde_json::to_value(&stats).unwrap();
    assert_eq!(json["overall"]["phases"], serde_json::json!([]));
}

#[test]
fn the_json_gives_each_phase_in_microseconds() {
    let store = Store::open_in_memory()
        .unwrap()
        .with_phase_times(&[("stdin", 40), ("taint", 700)]);
    let decision = Decision::new(Verdict::Allow);
    let event = NewEvent {
        host: Host::ALL[0].id(),
        session_id: "s",
        call_id: None,
        cwd: None,
        tool: "Bash",
        action: None,
        decision: &decision,
        latency_us: 800,
    };
    store.record_at(&event, 1_000).unwrap();
    let json = serde_json::to_value(stats(&store.since(0, None).unwrap())).unwrap();
    assert_eq!(
        json["overall"]["phases"],
        serde_json::json!([
            {"phase": "stdin", "calls": 1, "p50_us": 40, "p95_us": 40, "p99_us": 40, "max_us": 40},
            {"phase": "taint", "calls": 1, "p50_us": 700, "p95_us": 700, "p99_us": 700, "max_us": 700},
        ])
    );
    assert_eq!(json["agents"][0]["phases"][1]["phase"], "taint");
}

#[test]
fn the_json_document_names_its_format_and_window() {
    let json = serde_json::to_value(stats(&[])).unwrap();
    assert_eq!(json["format"], FORMAT);
    assert!(json["window"]["since"].is_string());
    assert!(json["overall"].is_object());
    assert!(json["agents"].is_array());
}
