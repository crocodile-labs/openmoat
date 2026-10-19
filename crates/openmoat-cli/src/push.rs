//! The push check of `moat guard` (docs/POLICY.md §4.2): before a `git push`
//! or a `gh pr create` runs, look at what it would publish.
//!
//! - A commit of the push that adds a known token shape or the value of a
//!   brokered secret denies it (`push-secret`): CI or anyone who can read the
//!   remote would get it.
//! - In a session that read untrusted content or a secret, a push that
//!   changes a `runs-later` file (a CI workflow, a hook manager's file) asks
//!   (`push-runs-later`): CI runs that file with the repository's secrets.
//! - What could not be checked in time, or past the size limit, asks
//!   (`push-unchecked`).
//! - Otherwise the decision stands as it was.
//!
//! The core finds the pushes (`openmoat_core::Push`); reading the repository
//! is I/O, so it is done here, with git, read-only, within [`BUDGET`].

mod git;
mod range;
mod scan;

use std::time::{Duration, Instant};

use openmoat_audit::KnownSecrets;
use openmoat_core::{Decision, Push, Verdict};

use git::{Git, Unchecked};

pub const SECRET_RULE: &str = "push-secret";
pub const RUNS_LATER_RULE: &str = "push-runs-later";
pub const UNCHECKED_RULE: &str = "push-unchecked";

/// The time all git commands of one call may take together, well inside the
/// guard's own budget (`install::GUARD_BUDGET_S`). Starting git can take
/// seconds on Windows and under load, and a push that runs out asks.
const BUDGET: Duration = Duration::from_secs(10);

/// Debug builds take the budget from this variable, in milliseconds, so the
/// end-to-end tests can reach the timeout. Release builds do not read it.
#[cfg(debug_assertions)]
const BUDGET_ENV: &str = "MOAT_TEST_PUSH_BUDGET_MS";

fn budget() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(BUDGET_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    BUDGET
}

/// What the pushes of one call publish, across every directory they may run in.
#[derive(Debug, Default)]
struct Findings {
    secret: Option<String>,
    runs_later: Vec<String>,
    unchecked: Vec<String>,
}

/// `decision` for a call whose shell command holds `pushes`, after the push
/// check. `known` holds the brokered secret values the guard can read;
/// `tainted` is whether the session read untrusted content or a secret. A
/// deny is returned as it is, without reading the repository.
pub fn check(pushes: &[Push], known: &KnownSecrets, tainted: bool, decision: Decision) -> Decision {
    if pushes.is_empty() || decision.verdict == Verdict::Deny {
        return decision;
    }
    let budget = budget();
    let findings = inspect(pushes, known, tainted, Instant::now() + budget, budget);
    if let Some(secret) = findings.secret {
        return tighten(
            decision,
            Verdict::Deny,
            SECRET_RULE,
            format!(
                "{secret}; a push publishes every commit it sends, so remove it from those \
                 commits first"
            ),
        );
    }
    let mut decision = decision;
    if tainted && !findings.runs_later.is_empty() {
        decision = tighten(
            decision,
            Verdict::Ask,
            RUNS_LATER_RULE,
            format!(
                "the session read untrusted content or a secret, and the push changes {}, \
                 which CI or a tool runs later with the repository's secrets",
                findings.runs_later.join(", ")
            ),
        );
    }
    for why in findings.unchecked {
        decision = tighten(
            decision,
            Verdict::Ask,
            UNCHECKED_RULE,
            format!("what the push would publish was not checked: {why}"),
        );
    }
    decision
}

fn inspect(
    pushes: &[Push],
    known: &KnownSecrets,
    tainted: bool,
    deadline: Instant,
    budget: Duration,
) -> Findings {
    let mut findings = Findings::default();
    for push in pushes {
        let spec = range::spec(&push.argv);
        for dir in &push.dirs {
            let Some(dir) = dir else {
                note(
                    &mut findings.unchecked,
                    "it may run in a directory or repository that is not known".to_owned(),
                );
                continue;
            };
            let git = Git::new(dir, deadline, budget);
            let scanned = range::revisions(&git, &spec).and_then(|revs| match revs {
                Some(revs) => scan::scan(&git, &revs, known, tainted).map(Some),
                None => Ok(None),
            });
            match scanned {
                Ok(Some(found)) => {
                    if found.secret.is_some() {
                        findings.secret = found.secret;
                        return findings;
                    }
                    for file in found.runs_later {
                        if !findings.runs_later.contains(&file) {
                            findings.runs_later.push(file);
                        }
                    }
                }
                Ok(None) => {}
                Err(Unchecked(why)) => note(&mut findings.unchecked, why),
            }
        }
    }
    findings
}

fn note(list: &mut Vec<String>, why: String) {
    if !list.contains(&why) {
        list.push(why);
    }
}

/// `decision` made at least as strict as `verdict` for `rule`. A stricter
/// verdict replaces the headline and keeps the earlier reasons as context.
fn tighten(mut decision: Decision, verdict: Verdict, rule: &str, reason: String) -> Decision {
    if decision.verdict > verdict {
        decision.context.push(reason);
        return decision;
    }
    if decision.verdict < verdict {
        let earlier: Vec<String> = decision.reasons.drain(..).collect();
        decision.context.extend(earlier);
        decision.rules.clear();
        decision.verdict = verdict;
    }
    if !decision.rules.iter().any(|r| r == rule) {
        decision.rules.push(rule.to_owned());
    }
    decision.reasons.push(reason);
    decision
}

#[cfg(test)]
mod testrepo;
#[cfg(test)]
mod tests;
