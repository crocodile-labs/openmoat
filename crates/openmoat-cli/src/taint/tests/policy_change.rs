//! A policy change (or an upgrade) late in a long session (ADR-121): every
//! digest is new, and the guard reads on from the session's furthest earlier
//! fold, carried forward, instead of folding the session from its first event
//! again and running out of time on every call.

use std::time::Instant;

use openmoat_audit::{EventId, Store};
use openmoat_core::{Action, CompiledPolicy, Policy};
use openmoat_hosts::Host;

use super::super::{CacheWrite, Pass, Progress, SessionTaint, catch_up, fold, of_session};
use super::{CWDS, ctx, far, read, record};

/// Reading `~/.ssh` is a secret read under the earlier policy.
const BEFORE: &str = "version: 1\ndefaults: { \"*\": allow }\nreview:\n  - { id: secrets-paths, \
                      fs.read: [\"~/.ssh/**\"] }\n";
/// The changed policy no longer names it.
const AFTER: &str = "version: 1\ndefaults: { \"*\": allow }\nreview:\n  - { id: secrets-paths, \
                     fs.read: [\"~/.gnupg/**\"] }\n";

fn compiled<'p>(policy: &'p Policy, cwd: &str) -> CompiledPolicy<'p> {
    CompiledPolicy::compile(policy, &ctx(cwd)).unwrap()
}

/// One guard call's lookup under `policy`, writing the cache as the guard
/// does.
fn call(
    store: &Store,
    policy: &Policy,
    cwd: &str,
    deadline: Instant,
) -> anyhow::Result<(SessionTaint, usize)> {
    let compiled = compiled(policy, cwd);
    let mut save = |write: &CacheWrite| write.write(store);
    let mut progress = Progress {
        deadline,
        save: &mut save,
        every: super::super::CHECKPOINT_EVERY,
        folded: 0,
    };
    let (taint, write) = of_session(store, Host::ClaudeCode, "s1", &compiled, cwd, &mut progress)?;
    if let Some(write) = write {
        write.write(store);
    }
    Ok((taint, progress.folded))
}

/// The session folded from its first event under `policy`, with no cache.
fn reference(store: &Store, policy: &Policy, cwd: &str) -> SessionTaint {
    let events = store.session_after("s1", EventId(0)).unwrap();
    let mut out = SessionTaint::default();
    fold(
        &mut out,
        &events,
        Host::ClaudeCode,
        &compiled(policy, cwd),
        cwd,
        &mut Pass::default(),
    )
    .unwrap();
    out
}

/// A session of `events` calls whose first read a secret under [`BEFORE`].
fn session(events: usize) -> Store {
    let store = Store::open_in_memory().unwrap();
    record(&store, CWDS[0], &read("/home/u/.ssh/id_rsa".to_owned()));
    for i in 1..events {
        record(&store, CWDS[0], &read(format!("/p/a/f{i}.rs")));
    }
    store
}

/// After the change the next call folds only the call recorded since and
/// keeps what the earlier policy found; once the fold under the new policy
/// has caught up after a call, it is what the guard reads.
#[test]
fn a_policy_change_reads_on_from_the_carried_fold_until_the_new_one_catches_up() {
    const EVENTS: usize = 2_000;
    let (before, after) = (
        Policy::parse(BEFORE).unwrap(),
        Policy::parse(AFTER).unwrap(),
    );
    let store = session(EVENTS);
    let (old, folded) = call(&store, &before, CWDS[0], far()).unwrap();
    assert_eq!(folded, EVENTS);
    assert_ne!(
        old,
        reference(&store, &after, CWDS[0]),
        "the change must change the fold"
    );

    record(&store, CWDS[0], &read("/p/a/next.rs".to_owned()));
    let budget = crate::commands::guard::taint_budget(Host::ClaudeCode);
    let started = Instant::now();
    let (carried, folded) = call(&store, &after, CWDS[0], started + budget).unwrap();
    assert_eq!(folded, 1, "the first call under the new policy read on");
    // Never looser than the earlier policy's answer: the secret read stays.
    assert_eq!(carried.taint, old.taint);
    // Another directory reads on from the same carried row.
    record(&store, CWDS[1], &read("/p/b/next.rs".to_owned()));
    let (_, folded) = call(&store, &after, CWDS[1], far()).unwrap();
    assert_eq!(folded, 1);

    // `PostToolUse` folds the session under the new policy from its first
    // event, and from then on that fold is the answer.
    catch_up(
        &store,
        Host::ClaudeCode,
        "s1",
        &compiled(&after, CWDS[0]),
        CWDS[0],
        far(),
    );
    record(&store, CWDS[0], &read("/p/a/last.rs".to_owned()));
    let (exact, folded) = call(&store, &after, CWDS[0], far()).unwrap();
    assert_eq!(folded, 1);
    assert_eq!(exact, reference(&store, &after, CWDS[0]));
}

/// A `catch_up` that runs out of time keeps what it reached, and the carried
/// fold keeps answering meanwhile; the next `catch_up` reads on.
#[test]
fn an_unfinished_catch_up_leaves_the_carried_fold_in_charge() {
    const EVENTS: usize = 1_000;
    let (before, after) = (
        Policy::parse(BEFORE).unwrap(),
        Policy::parse(AFTER).unwrap(),
    );
    let store = session(EVENTS);
    let (old, _) = call(&store, &before, CWDS[0], far()).unwrap();
    let after_here = compiled(&after, CWDS[0]);
    catch_up(
        &store,
        Host::ClaudeCode,
        "s1",
        &after_here,
        CWDS[0],
        Instant::now(),
    );
    let (carried, folded) = call(&store, &after, CWDS[0], far()).unwrap();
    assert_eq!(folded, 0);
    assert_eq!(carried, old);
    catch_up(&store, Host::ClaudeCode, "s1", &after_here, CWDS[0], far());
    let (exact, folded) = call(&store, &after, CWDS[0], far()).unwrap();
    assert_eq!(folded, 0);
    assert_eq!(exact, reference(&store, &after, CWDS[0]));
}

/// A fold that took a call recorded without a directory to have run in
/// another directory is no fold to carry: the session is folded from its
/// first event, as before.
#[test]
fn a_fold_holding_a_call_without_a_directory_is_not_carried() {
    let (before, after) = (
        Policy::parse(BEFORE).unwrap(),
        Policy::parse(AFTER).unwrap(),
    );
    let store = session(10);
    super::record_in(
        &store,
        None,
        &Action::FsRead {
            path: "rel.rs".to_owned(),
        },
    );
    let (old, _) = call(&store, &before, CWDS[0], far()).unwrap();
    assert!(old.cwdless);
    let (taint, folded) = call(&store, &after, CWDS[0], far()).unwrap();
    assert_eq!(folded, 11);
    assert_eq!(taint, reference(&store, &after, CWDS[0]));
}
