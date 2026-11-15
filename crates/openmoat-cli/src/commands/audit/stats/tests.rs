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
    let store = Store::open_in_memory().unwrap();
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
}

#[test]
fn the_json_document_names_its_format_and_window() {
    let json = serde_json::to_value(stats(&[])).unwrap();
    assert_eq!(json["format"], FORMAT);
    assert!(json["window"]["since"].is_string());
    assert!(json["overall"].is_object());
    assert!(json["agents"].is_array());
}
