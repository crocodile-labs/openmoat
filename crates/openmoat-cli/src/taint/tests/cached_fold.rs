//! The cached fold against a fold of the whole session, over a long random
//! session: the property the cache rows, the directories and the deadlines
//! must keep together.

use std::time::Instant;

use openmoat_audit::{EventId, Store};
use openmoat_core::{Action, CompiledPolicy, Policy};
use openmoat_hosts::Host;

use super::super::{Pass, SessionTaint, catch_up, fold};
use super::{POLICY, call, ctx, far, read, record_in, reference};

/// The cached fold answers what a fold of the whole session from its first
/// event answers, in every directory, at every call: over a session whose
/// calls ran in several directories, some recorded without one, read files by
/// a path relative to their directory (a secret only from one of them) and
/// fetched untrusted content, decided from directories in turn, with calls
/// stopped by their deadline and `PostToolUse` catch-ups between them.
#[test]
fn the_cached_fold_is_a_full_fold_in_every_directory() {
    const DIRS: [&str; 3] = ["/p/a", "/p/b", "/home/u/work"];
    let store = Store::open_in_memory().unwrap();
    let policy = Policy::parse(POLICY).unwrap();
    // a fixed pseudo-random sequence, so a failure replays
    let mut seed: u64 = 0x5eed;
    let mut next = |n: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).unwrap() % n
    };
    let mut differed = false;
    // The reference is the full fold kept up to date: each directory's fold
    // from the first event, taken on with only the events recorded since (a
    // fold is a left fold over the events, so this is the full fold), and
    // checked against `reference`, a fold from the first event, at every
    // checkpoint. Folding the whole session again at each step made the test
    // quadratic in its steps: minutes on the slowest CI runner.
    let mut full = FullFolds::new(&policy, &DIRS);
    for step in 0..200 {
        let recorded = match next(5) {
            4 => None,
            d => Some(DIRS[d % DIRS.len()]),
        };
        let action = match next(20) {
            0 => Action::Fetch {
                url: format!("https://example.com/{step}"),
            },
            1..=3 => read("../.ssh/id_rsa".to_owned()),
            4..=6 => read(format!("f{step}.rs")),
            _ => read(format!("/p/a/f{step}.rs")),
        };
        // Untrusted content late, so most of the session is folded clean.
        if step > 40 || !matches!(action, Action::Fetch { .. }) {
            record_in(&store, recorded, &action);
        }
        let cwd = DIRS[next(DIRS.len())];
        match next(6) {
            0 => assert!(call(&store, cwd, Instant::now()).is_err(), "step {step}"),
            1 => {
                let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
                catch_up(&store, Host::ClaudeCode, "s1", &compiled, cwd, far());
            }
            _ => {
                let (taint, _) = call(&store, cwd, far()).unwrap();
                assert_eq!(taint, *full.at(&store, cwd), "step {step} in {cwd}");
            }
        }
        // Every 25 steps, a fold from the first event in each directory: the
        // kept folds are those, and whether the directory changed the answer.
        if step % 25 == 24 {
            let folds: Vec<SessionTaint> = DIRS.iter().map(|d| reference(&store, d)).collect();
            for (dir, fold) in DIRS.iter().zip(&folds) {
                assert_eq!(
                    full.at(&store, dir),
                    fold,
                    "step {step}: kept fold in {dir}"
                );
            }
            differed |= folds.iter().any(|f| f.taint != folds[0].taint);
        }
    }
    assert!(differed, "no step's fold depended on the directory");
}

/// Each directory's fold of the whole session, without the cache, taken on
/// with the events recorded since it was last asked.
struct FullFolds<'p> {
    dirs: Vec<(&'static str, CompiledPolicy<'p>, SessionTaint, EventId)>,
}

impl<'p> FullFolds<'p> {
    fn new(policy: &'p Policy, dirs: &[&'static str]) -> Self {
        let dirs = dirs
            .iter()
            .map(|&d| {
                let compiled = CompiledPolicy::compile(policy, &ctx(d)).unwrap();
                (d, compiled, SessionTaint::default(), EventId(0))
            })
            .collect();
        Self { dirs }
    }

    /// The fold in `cwd` of every event recorded so far.
    fn at(&mut self, store: &Store, cwd: &str) -> &SessionTaint {
        let (_, compiled, out, last) = self.dirs.iter_mut().find(|(d, ..)| *d == cwd).unwrap();
        let events = store.session_after("s1", *last).unwrap();
        let taken = fold(
            out,
            &events,
            Host::ClaudeCode,
            compiled,
            cwd,
            &mut Pass::default(),
        )
        .unwrap();
        assert_eq!(taken, events.len());
        if let Some(event) = events.last() {
            *last = event.id;
        }
        out
    }
}
