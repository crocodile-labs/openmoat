//! The hook waiting for an answer (ADR-093): how long, from each host's spec;
//! only while a listener's signed beat is fresh; an approval or a deny that
//! arrives meanwhile decides the call, once; nothing in time, or anything
//! wrong, leaves the review exactly as without the wait.

use std::time::{Duration, Instant};

use openmoat_audit::KnownSecrets;
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{FailureOutcome, GUARD_BUDGET_S, HookFailure, HookRequest, Host};

use super::super::answer::{self, Answer};
use super::super::gate::gate_used;
use super::super::listen::{Listener, Records, Row};
use super::super::live::{self, LIVE_MS};
use super::super::refused::Approved;
use super::super::wait::{
    ANSWER_MARGIN, FAIL_OPEN_SHARE, Hold, MAX_WAIT_S, RELAY_MARGIN, host_limit, room,
};
use super::{
    APPROVED_RULE, APPROVER, APPROVER_ID, DENIED_RULE, FAKE, Fake, Rows, Setup, approve_button,
    call, only_request, press, review, setup,
};
use crate::proxy_session::Key;

fn now() -> i64 {
    crate::time::now_ms()
}

fn failure(times_out: FailureOutcome, timeout_s: Option<u32>) -> HookFailure {
    HookFailure {
        times_out,
        timeout_s,
        ..HookFailure::BASE
    }
}

/// The gate at the real time, holding the hook up to `room`.
fn gate_for(s: &Setup, request: &HookRequest, room: Duration) -> (Decision, Option<Approved>) {
    let hold = Hold {
        until: Instant::now() + room,
        clock: &crate::time::now_ms,
    };
    gate_used(
        &s.store,
        request,
        review(),
        &KnownSecrets::default(),
        (now(), &hold),
    )
}

/// An approver's answer to the one request on file, written as `listen`
/// writes it, once the guard has sent the request.
fn answer_when_sent(s: &Setup, verdict: answer::Verdict, after: Duration) {
    let started = Instant::now();
    let request = loop {
        let found: Vec<_> = s.store.requests().unwrap().into_iter().flatten().collect();
        if let Some(request) = found.into_iter().next() {
            break request;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "never sent");
        std::thread::sleep(Duration::from_millis(10));
    };
    std::thread::sleep(after);
    let answer = Answer::signed(&s.key, &request, (verdict, APPROVER_ID, "fake"), now()).unwrap();
    assert!(s.store.put_answer(&answer).unwrap());
}

#[test]
fn every_host_s_wait_ends_safely_before_its_hook_times_out() {
    for host in Host::ALL {
        let facts = &host.spec().hook_failure;
        let limit = room(facts, Duration::ZERO, false);
        let whole = limit + ANSWER_MARGIN;
        assert!(
            whole <= Duration::from_secs(GUARD_BUDGET_S),
            "{host:?}: {whole:?}"
        );
        let Some(timeout) = facts.timeout_s else {
            assert_eq!(limit, Duration::ZERO, "{host:?} documents no timeout");
            continue;
        };
        let timeout = Duration::from_secs(u64::from(timeout));
        if facts.times_out == FailureOutcome::Blocks {
            assert!(whole <= timeout, "{host:?}");
        } else {
            // Where a timed-out hook lets the call run, far below the timeout.
            assert!(
                whole * FAIL_OPEN_SHARE <= timeout || limit.is_zero(),
                "{host:?}: {whole:?} of {timeout:?}"
            );
        }
        // Under `openmoat run` the relay's share comes off too.
        assert_eq!(
            room(facts, Duration::ZERO, true),
            limit.saturating_sub(RELAY_MARGIN),
            "{host:?}"
        );
    }
}

#[test]
fn the_wait_is_capped_by_the_host_the_budget_and_the_time_already_spent() {
    let blocks = failure(FailureOutcome::Blocks, Some(30));
    assert_eq!(host_limit(&blocks), Duration::from_secs(30));
    assert_eq!(
        room(&blocks, Duration::ZERO, false),
        Duration::from_secs(25)
    );
    assert_eq!(
        room(&blocks, Duration::from_secs(24), false),
        Duration::from_secs(1)
    );
    assert_eq!(
        room(&blocks, Duration::from_secs(30), false),
        Duration::ZERO
    );
    assert_eq!(room(&blocks, Duration::ZERO, true), Duration::from_secs(20));
    // A host that runs a timed-out call: a quarter of its timeout at most.
    for open in [
        FailureOutcome::Runs,
        FailureOutcome::NotDocumented,
        FailureOutcome::BlocksFrom((1, 0, 0)),
    ] {
        assert_eq!(
            room(&failure(open, Some(600)), Duration::ZERO, false),
            Duration::from_secs(25)
        );
        assert_eq!(
            room(&failure(open, Some(60)), Duration::ZERO, false),
            Duration::from_secs(10)
        );
        assert_eq!(
            room(&failure(open, Some(20)), Duration::ZERO, false),
            Duration::ZERO
        );
    }
    // No documented timeout: never.
    assert_eq!(
        room(
            &failure(FailureOutcome::Blocks, None),
            Duration::ZERO,
            false
        ),
        Duration::ZERO
    );
    assert_eq!(MAX_WAIT_S + ANSWER_MARGIN.as_secs(), GUARD_BUDGET_S);
}

#[test]
fn only_a_fresh_beat_signed_with_the_key_is_a_listener() {
    let s = setup();
    let t = now();
    assert!(!live::live(&s.store, &s.key, "fake", t), "no beat");
    live::beat(&s.store, &s.key, "fake", t).unwrap();
    assert!(live::live(&s.store, &s.key, "fake", t));
    assert!(live::live(&s.store, &s.key, "fake", t + LIVE_MS));
    assert!(
        !live::live(&s.store, &s.key, "fake", t + LIVE_MS + 1),
        "stale"
    );
    assert!(!live::live(&s.store, &s.key, "other", t), "another channel");
    assert!(
        !live::live(&s.store, &s.key, "fake", t - 60_000),
        "from the future"
    );
    let other = Key::load_or_create_at(&s.store.dir().join("other.key")).unwrap();
    assert!(!live::live(&s.store, &other, "fake", t), "another key");
    // An edited time does not verify.
    let path = s.store.dir().join("listening.json");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace(&t.to_string(), &(t + 1).to_string())).unwrap();
    assert!(!live::live(&s.store, &s.key, "fake", t));
    live::stop(&s.store);
    assert!(!path.exists());
}

#[test]
fn a_listener_round_writes_its_beat() {
    let s = setup();
    let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
    let t = now();
    listener
        .step(
            &mut Fake::default(),
            &mut Rows::default(),
            Duration::ZERO,
            &|| t,
        )
        .unwrap();
    assert!(live::live(&s.store, &s.key, "fake", t));
}

#[test]
fn without_a_listener_the_hook_does_not_wait() {
    let s = setup();
    let started = Instant::now();
    let (d, used) = gate_for(&s, &call("s1", "npm publish"), Duration::from_secs(10));
    assert!(started.elapsed() < Duration::from_secs(1), "waited");
    assert_eq!(d.verdict, Verdict::Review);
    assert!(used.is_none());
    assert!(!d.reasons.iter().any(|r| r.contains("no answer")), "{d:?}");
    // A beat another key signed (one an agent could make) is no listener.
    let other = Key::load_or_create_at(&s.store.dir().join("other.key")).unwrap();
    live::beat(&s.store, &other, "fake", now()).unwrap();
    let started = Instant::now();
    let (d, _) = gate_for(&s, &call("s1", "npm publish"), Duration::from_secs(10));
    assert!(started.elapsed() < Duration::from_secs(1), "waited");
    assert_eq!(d.verdict, Verdict::Review);
}

#[test]
fn a_wait_of_zero_never_waits() {
    let mut s = setup();
    s.settings.set_wait(0).unwrap();
    s.settings.save(&s.store.settings_path(), &s.key).unwrap();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let started = Instant::now();
    let (d, _) = gate_for(&s, &call("s1", "npm publish"), Duration::from_secs(10));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(d.verdict, Verdict::Review);
    assert!(s.settings.set_wait(MAX_WAIT_S + 1).is_err());
}

#[test]
fn an_approval_during_the_wait_allows_this_call_once() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let req = call("s1", "npm publish");
    let started = Instant::now();
    let (d, used) = std::thread::scope(|scope| {
        scope.spawn(|| answer_when_sent(&s, answer::Verdict::Approve, Duration::from_millis(300)));
        gate_for(&s, &req, Duration::from_secs(5))
    });
    let took = started.elapsed();
    assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
    assert_eq!(d.rules, [APPROVED_RULE]);
    assert!(d.reasons[0].contains(APPROVER_ID), "{d:?}");
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("while the hook waited"))
    );
    assert!(used.is_some(), "the approval is used");
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(5),
        "{took:?}"
    );
    // Used: the next try is a new request, and the old one is gone.
    let (next, _) = gate_for(&s, &req, Duration::ZERO);
    assert_eq!(next.verdict, Verdict::Review);
    assert_eq!(s.store.requests().unwrap().len(), 1);
}

#[test]
fn a_deny_during_the_wait_denies_at_once() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let started = Instant::now();
    let (d, used) = std::thread::scope(|scope| {
        scope.spawn(|| answer_when_sent(&s, answer::Verdict::Deny, Duration::from_millis(200)));
        gate_for(&s, &call("s1", "npm publish"), Duration::from_secs(5))
    });
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
    assert_eq!(d.rules, [DENIED_RULE]);
    assert!(used.is_none());
}

#[test]
fn no_answer_in_time_keeps_the_review_and_the_request() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let started = Instant::now();
    let (d, used) = gate_for(&s, &call("s1", "npm publish"), Duration::from_millis(700));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_secs(2),
        "{took:?}"
    );
    assert_eq!(d.verdict, Verdict::Review);
    assert!(used.is_none());
    assert!(
        d.reasons.iter().any(|r| r.contains("no answer over fake")),
        "{d:?}"
    );
    // The request still waits for the next try.
    only_request(&s);
}

#[test]
fn a_forged_answer_during_the_wait_changes_nothing() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let other = Key::load_or_create_at(&s.store.dir().join("other.key")).unwrap();
    let (d, _) = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            let request = only_request(&s);
            let forged = Answer::signed(
                &other,
                &request,
                (answer::Verdict::Approve, APPROVER_ID, "fake"),
                now(),
            )
            .unwrap();
            s.store.put_answer(&forged).unwrap();
        });
        gate_for(&s, &call("s1", "npm publish"), Duration::from_millis(600))
    });
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(!s.store.used(&only_request(&s).id));
}

#[test]
fn an_approver_removed_during_the_wait_no_longer_counts() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let (d, _) = std::thread::scope(|scope| {
        scope.spawn(|| {
            let started = Instant::now();
            while s.store.requests().unwrap().is_empty() {
                assert!(started.elapsed() < Duration::from_secs(5), "never sent");
                std::thread::sleep(Duration::from_millis(10));
            }
            // The guard read the settings when it started; the person
            // removes the approver, who then answers.
            let mut gone = s.settings.clone();
            gone.approvers.clear();
            gone.save(&s.store.settings_path(), &s.key).unwrap();
            answer_when_sent(&s, answer::Verdict::Approve, Duration::ZERO);
        });
        gate_for(&s, &call("s1", "npm publish"), Duration::from_millis(800))
    });
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(!s.store.used(&only_request(&s).id));
}

#[test]
fn two_waiting_guards_use_one_approval_once() {
    let s = setup();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let req = call("s1", "npm publish");
    // The first try sends the request; two retries wait on it.
    let (first, _) = gate_for(&s, &req, Duration::ZERO);
    assert_eq!(first.verdict, Verdict::Review);
    let decisions: Vec<Decision> = std::thread::scope(|scope| {
        let guards: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| gate_for(&s, &req, Duration::from_secs(3)).0))
            .collect();
        scope.spawn(|| answer_when_sent(&s, answer::Verdict::Approve, Duration::from_millis(200)));
        guards.into_iter().map(|g| g.join().unwrap()).collect()
    });
    let allowed = decisions
        .iter()
        .filter(|d| d.verdict == Verdict::Allow)
        .count();
    assert_eq!(allowed, 1, "{decisions:?}");
    assert!(
        decisions
            .iter()
            .any(|d| d.verdict == Verdict::Review && d.reasons.iter().any(|r| r.contains("used"))),
        "{decisions:?}"
    );
}

#[test]
fn the_wait_ends_when_the_beat_goes_stale() {
    let s = setup();
    // Live now, stale in about a second: the listener stopped beating.
    live::beat(&s.store, &s.key, "fake", now() - (LIVE_MS - 1_000)).unwrap();
    let started = Instant::now();
    let (d, _) = gate_for(&s, &call("s1", "npm publish"), Duration::from_secs(8));
    let took = started.elapsed();
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
}

#[test]
fn the_wait_ends_when_the_request_expires() {
    let s = setup();
    let req = call("s1", "npm publish");
    gate_for(&s, &req, Duration::ZERO);
    // The request on file expires in under a second.
    let mut request = only_request(&s);
    request.expires_ms = now() + 700;
    request.sign(&s.key).unwrap();
    s.store.put_request(&request).unwrap();
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let started = Instant::now();
    let (d, _) = gate_for(&s, &req, Duration::from_secs(8));
    let took = started.elapsed();
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
}

/// Records whose write takes a while and then fails, as a locked or full
/// audit log would.
struct SlowThenFails;

impl Records for SlowThenFails {
    fn record(&mut self, _: Row) -> anyhow::Result<()> {
        std::thread::sleep(Duration::from_millis(500));
        anyhow::bail!("audit log unavailable")
    }
}

#[test]
fn an_approval_whose_row_fails_is_never_used_by_a_waiting_guard() {
    let s = setup();
    let req = call("s1", "npm publish");
    gate_for(&s, &req, Duration::ZERO);
    let request = only_request(&s);
    live::beat(&s.store, &s.key, "fake", now()).unwrap();
    let (d, answered) = std::thread::scope(|scope| {
        let listening = scope.spawn(|| {
            let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
            let reply = press(APPROVER, &approve_button(&s, &request));
            listener.answer(&mut Fake::default(), &mut SlowThenFails, &[reply], &now)
        });
        let decided = gate_for(&s, &req, Duration::from_millis(1_500)).0;
        (decided, listening.join().unwrap())
    });
    answered.unwrap();
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(!s.store.used(&request.id), "the approval was not used");
    assert!(!s.store.has_answer(&request.id), "no answer stands");
}
