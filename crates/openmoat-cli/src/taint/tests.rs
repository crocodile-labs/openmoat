use std::time::{Duration, Instant};

use openmoat_audit::{EventId, NewEvent, Store};
use openmoat_core::{Action, CompiledPolicy, Decision, EvalContext, Policy, Verdict};
use openmoat_hosts::Host;

use super::{CacheWrite, Pass, Progress, SessionTaint, after_read, digest, fold, of_session};
use crate::realpath::FsPathResolver;

#[test]
fn a_grant_is_ordered_against_the_read_by_row_whatever_the_clock_says() {
    // The clock stepped back after the read: the grant looks older by
    // time, but it saw the read's row, so it answers.
    assert!(after_read(1_000, Some(7), 2_000, Some(5)));
    assert!(after_read(1_000, Some(5), 2_000, Some(5)));
    // The clock stepped back before the read: the grant looks newer by
    // time, but the read came after every row it saw, so it does not.
    assert!(!after_read(3_000, Some(4), 2_000, Some(5)));
}

#[test]
fn a_grant_without_a_row_is_ordered_by_time() {
    assert!(after_read(3_000, None, 2_000, Some(5)));
    assert!(!after_read(2_000, None, 2_000, Some(5)));
    assert!(!after_read(1_000, None, 2_000, Some(5)));
}

const POLICY: &str = "version: 1\ndefaults: { \"*\": allow }\n";
const CWDS: [&str; 2] = ["/p/a", "/p/b"];

fn ctx(cwd: &str) -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: cwd.to_owned(),
        case_insensitive_paths: false,
    }
}

fn record(store: &Store, cwd: &str, action: &Action) {
    let decision = Decision::new(Verdict::Allow);
    store
        .record(&NewEvent {
            host: Host::ClaudeCode.id(),
            session_id: "s1",
            call_id: None,
            cwd: Some(cwd),
            tool: "tool",
            action: Some(action),
            decision: &decision,
            latency_us: 0,
        })
        .unwrap();
}

fn read(path: String) -> Action {
    Action::FsRead { path }
}

fn far() -> Instant {
    Instant::now() + Duration::from_hours(1)
}

/// One guard call's taint lookup in `cwd`, writing the cache as the guard
/// does: what it folded to, and how many events it classified.
fn call(store: &Store, cwd: &str, deadline: Instant) -> anyhow::Result<(SessionTaint, usize)> {
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
    let mut save = |write: &CacheWrite| write.write(store);
    let mut progress = Progress {
        deadline,
        save: &mut save,
        folded: 0,
    };
    let (taint, write) = of_session(store, Host::ClaudeCode, "s1", &compiled, cwd, &mut progress)?;
    if let Some(write) = write {
        write.write(store);
    }
    Ok((taint, progress.folded))
}

/// The session folded from its first event in one go, with no cache: what
/// every call answered before the cache existed.
fn reference(store: &Store, cwd: &str) -> SessionTaint {
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
    let events = store.session_after("s1", EventId(0)).unwrap();
    let mut out = SessionTaint::default();
    let taken = fold(
        &mut out,
        &events,
        Host::ClaudeCode,
        &compiled,
        cwd,
        &mut Pass::default(),
    )
    .unwrap();
    assert_eq!(taken, events.len());
    out
}

/// Calls that alternate between two directories each read on from their own
/// cache row: over many calls each event is classified about once per
/// directory, not once per call (before, every call folded the whole
/// session again).
#[test]
fn alternating_directories_fold_each_event_a_bounded_number_of_times() {
    const EVENTS: usize = 2_000;
    const CALLS: usize = 20;
    let store = Store::open_in_memory().unwrap();
    for i in 0..EVENTS {
        let cwd = CWDS[i % 2];
        record(&store, cwd, &read(format!("{cwd}/f{i}.rs")));
    }
    let mut total = 0;
    for n in 0..CALLS {
        let cwd = CWDS[n % 2];
        let (_, folded) = call(&store, cwd, far()).unwrap();
        total += folded;
        record(&store, cwd, &read(format!("{cwd}/x{n}.rs")));
    }
    // A full fold per directory, then only the calls recorded since.
    assert!(
        total <= CWDS.len() * (EVENTS + CALLS),
        "{total} events folded over {CALLS} calls"
    );
}

/// A session that read untrusted content in one directory is tainted for a
/// protected write in another, with or without the cache, at every call.
#[test]
fn verdicts_are_those_of_a_full_fold_in_every_directory() {
    let store = Store::open_in_memory().unwrap();
    let policy = Policy::parse(POLICY).unwrap();
    let write = Action::FsWrite {
        path: "/p/b/.github/workflows/ci.yml".to_owned(),
    };
    for n in 0..12 {
        let cwd = CWDS[n % 2];
        match n {
            3 => record(
                &store,
                CWDS[0],
                &Action::Fetch {
                    url: "https://example.com/page".to_owned(),
                },
            ),
            _ => record(&store, cwd, &read(format!("{cwd}/f{n}.rs"))),
        }
        for cwd in CWDS {
            let (taint, _) = call(&store, cwd, far()).unwrap();
            assert_eq!(taint, reference(&store, cwd), "call {n} in {cwd}");
            assert_eq!(taint.taint.untrusted.is_some(), n >= 3, "call {n} in {cwd}");
            let compiled = CompiledPolicy::compile(&policy, &ctx(CWDS[1])).unwrap();
            let decision = compiled.with_taint(
                Decision::new(Verdict::Allow),
                &write,
                &FsPathResolver,
                &taint.taint,
            );
            let expected = if n >= 3 { Verdict::Ask } else { Verdict::Allow };
            assert_eq!(decision.verdict, expected, "call {n} in {cwd}");
        }
    }
}

/// A fold that runs out of time is never an answer: the call fails (the
/// guard denies) whether or not a cache row exists, and the row stays as it
/// was. A fold saved part way, as a stopped fold saves it, reads on to the
/// full fold's verdict, untrusted read included.
#[test]
fn an_interrupted_fold_never_answers_cleaner() {
    let store = Store::open_in_memory().unwrap();
    for n in 0..10 {
        record(&store, CWDS[0], &read(format!("/p/a/f{n}.rs")));
    }
    let past = Instant::now();
    assert!(call(&store, CWDS[0], past).is_err());
    let (clean, _) = call(&store, CWDS[0], far()).unwrap();
    assert_eq!(clean.taint.untrusted, None);
    record(
        &store,
        CWDS[0],
        &Action::Fetch {
            url: "https://example.com/page".to_owned(),
        },
    );
    // The clean row is there, but a stopped fold does not answer from it.
    assert!(call(&store, CWDS[0], past).is_err());
    let (tainted, folded) = call(&store, CWDS[0], far()).unwrap();
    assert_eq!(folded, 1, "read on from the clean row");
    assert!(tainted.taint.untrusted.is_some());
    assert_eq!(tainted, reference(&store, CWDS[0]));

    // A row saved part way through another directory's fold.
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(CWDS[1])).unwrap();
    let events = store.session_after("s1", EventId(0)).unwrap();
    let (head, _) = events.split_at(5);
    let mut partial = SessionTaint::default();
    fold(
        &mut partial,
        head,
        Host::ClaudeCode,
        &compiled,
        CWDS[1],
        &mut Pass::default(),
    )
    .unwrap();
    assert_eq!(partial.taint.untrusted, None);
    CacheWrite {
        session: "s1".to_owned(),
        host: Host::ClaudeCode,
        cached: openmoat_audit::Cached {
            digest: digest(Host::ClaudeCode, &compiled, CWDS[1]).unwrap(),
            upto: head[4].id,
            state: serde_json::to_string(&partial).unwrap(),
        },
    }
    .write(&store);
    let (resumed, folded) = call(&store, CWDS[1], far()).unwrap();
    assert_eq!(folded, events.len() - 5);
    assert_eq!(resumed, reference(&store, CWDS[1]));
    assert!(resumed.taint.untrusted.is_some());
}
