//! How much OpenMoat got in the way of normal work, from the audit log alone:
//! calls checked, decision time percentiles, verdict counts and rates, calls
//! held and later allowed, and the guard's own failures, per agent and over
//! all agents. `openmoat audit stats` reads them from a person's log over a
//! window; `openmoat bench` from the throwaway log of its everyday scenarios.
//!
//! Only measured figures are produced: a window with no calls has no
//! percentiles, not zeros. What each agent does when the hook fails is its
//! spec's (ADR-079), not measured.

use std::collections::{BTreeMap, HashSet};

use openmoat_audit::Event;
use openmoat_core::Verdict;
use openmoat_core::rule_id::{APPROVED_REMOTE, APPROVED_SESSION, KERNEL_ERROR, RUN_GUARD_OUTSIDE};
use openmoat_hosts::{FailureOutcome, Host};
use serde::Serialize;

#[cfg(test)]
mod tests;

/// The figures over all agents and per agent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Disturbance {
    /// Every agent's calls together.
    pub overall: Figures,
    /// One entry per agent with calls in the window, in the order commands
    /// list agents.
    pub agents: Vec<AgentFigures>,
    /// Rows of the window that are not an agent's tool call (the proxy's, a
    /// run's, an approval's, a delivery's): left out of every figure.
    pub other_rows: u64,
}

/// One agent's figures, with what it does when the hook fails.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentFigures {
    /// The agent's id, as the audit log records it.
    pub host: &'static str,
    /// The agent's name.
    pub name: &'static str,
    /// Its figures.
    #[serde(flatten)]
    pub figures: Figures,
    /// What the agent does with a call when the hook fails, from its spec.
    pub hook_failure: HookFailureFacts,
}

/// An agent's hook-failure facts in words (ADR-079): documented, not measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookFailureFacts {
    /// The hook cannot start, crashes or exits without a decision.
    pub fails: String,
    /// The hook does not answer within `timeout_s`.
    pub times_out: String,
    /// The hook's time limit as `openmoat init` installs it, in seconds.
    pub timeout_s: Option<u32>,
    /// Seconds after which the guard answers deny on its own for this agent
    /// (ADR-120).
    pub deadline_s: u64,
}

impl HookFailureFacts {
    fn of(host: Host) -> Self {
        let spec = host.spec();
        let facts = spec.hook_failure;
        let deadline_s = spec.guard_deadline_s();
        Self {
            fails: FailureOutcome::words(facts.fails),
            times_out: facts.times_out.words_at(Some(deadline_s)),
            timeout_s: facts.timeout_s,
            deadline_s,
        }
    }
}

/// The figures of one set of calls.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Figures {
    /// Tool calls the guard decided and recorded.
    pub calls: u64,
    /// Calls per verdict.
    pub verdicts: Verdicts<u64>,
    /// Calls per verdict, per 100 calls (`review` is the prompts OpenMoat
    /// added; `defer` leaves the agent's own prompt as it was).
    pub per_100_calls: Verdicts<f64>,
    /// Decision time; `None` without calls.
    pub latency: Option<Latency>,
    /// Calls that ran because a person approved them (`openmoat allow` for the
    /// session, or an approval from another device).
    pub approved: u64,
    /// Denies whose same call, in the same session, was allowed later: the
    /// log's nearest sign of a deny a person did not want.
    pub denies_later_allowed: u64,
    /// Reviews whose same call, in the same session, was allowed later.
    pub reviews_later_allowed: u64,
    /// Calls the guard denied because it could not check or record them
    /// (`kernel-error`).
    pub kernel_errors: u64,
    /// Calls the guard denied because no decision came within its budget,
    /// from the hangs file: the audit log cannot hold them.
    pub guard_timeouts: u64,
}

/// One value per verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Verdicts<T> {
    /// `allow`.
    pub allow: T,
    /// `defer`: the agent's own permission flow decides.
    pub defer: T,
    /// `review`: a person decides.
    pub review: T,
    /// `deny`.
    pub deny: T,
}

/// Decision time percentiles, nearest rank, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Latency {
    /// Half the calls took at most this long.
    #[serde(rename = "p50_us")]
    pub p50: u64,
    /// 95 in 100 calls took at most this long.
    #[serde(rename = "p95_us")]
    pub p95: u64,
    /// 99 in 100 calls took at most this long.
    #[serde(rename = "p99_us")]
    pub p99: u64,
    /// The slowest call.
    #[serde(rename = "max_us")]
    pub max: u64,
}

impl Latency {
    /// The percentiles of `samples`; `None` when there are none.
    pub fn of(mut samples: Vec<u64>) -> Option<Self> {
        samples.sort_unstable();
        let at = |percent: usize| -> Option<u64> {
            // Nearest rank: the smallest sample with at least `percent` in 100
            // of the samples at or below it.
            let rank = (percent * samples.len()).div_ceil(100).max(1);
            samples.get(rank - 1).copied()
        };
        Some(Self {
            p50: at(50)?,
            p95: at(95)?,
            p99: at(99)?,
            max: *samples.last()?,
        })
    }
}

/// `count` per 100 of `total`, to two decimals; 0 when `total` is 0.
fn per_100(count: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    // In hundredths, rounded half up: at most 10 000, so exact in an f64.
    let centi = (count.saturating_mul(10_000) + total / 2) / total;
    f64::from(u32::try_from(centi).unwrap_or(u32::MAX)) / 100.0
}

/// The agent whose tool call `event` records; `None` for any other row.
fn agent_of(event: &Event) -> Option<Host> {
    let host = Host::EVERY.into_iter().find(|h| h.id() == event.host)?;
    let bookkeeping = event.tool == crate::remote::ROW_TOOL
        || event.tool == openmoat_audit::RAN_AFTER_REVIEW_TOOL
        || event.rules.iter().any(|r| r == RUN_GUARD_OUTSIDE);
    (!bookkeeping).then_some(host)
}

/// The figures of `events` (oldest first, as the store returns them), with
/// each agent's guard timeouts from `timeouts`.
pub fn of(events: &[Event], timeouts: &[(Host, u64)]) -> Disturbance {
    let later = later_allowed(events);
    let mut per_agent: BTreeMap<usize, (Host, Tally)> = BTreeMap::new();
    let mut other_rows = 0;
    for (i, event) in events.iter().enumerate() {
        let Some(host) = agent_of(event) else {
            other_rows += 1;
            continue;
        };
        let order = Host::EVERY.iter().position(|h| *h == host).unwrap_or(0);
        let tally = &mut per_agent.entry(order).or_insert((host, Tally::default())).1;
        tally.add(event, later.contains(&i));
    }
    for &(host, count) in timeouts {
        let order = Host::EVERY.iter().position(|h| *h == host).unwrap_or(0);
        per_agent
            .entry(order)
            .or_insert((host, Tally::default()))
            .1
            .figures
            .guard_timeouts += count;
    }
    let mut overall = Tally::default();
    let agents = per_agent
        .into_values()
        .map(|(host, tally)| {
            overall.merge(&tally);
            AgentFigures {
                host: host.id(),
                name: host.display_name(),
                figures: tally.finish(),
                hook_failure: HookFailureFacts::of(host),
            }
        })
        .collect();
    Disturbance {
        overall: overall.finish(),
        agents,
        other_rows,
    }
}

/// The indices of the denies and reviews whose same call (agent, session and
/// recorded action) an event after them allowed.
fn later_allowed(events: &[Event]) -> HashSet<usize> {
    let mut allowed_after: HashSet<(&str, &str, String)> = HashSet::new();
    let mut found = HashSet::new();
    for (i, event) in events.iter().enumerate().rev() {
        let Some(action) = event.action.as_ref() else {
            continue;
        };
        let Ok(action) = serde_json::to_string(action) else {
            continue;
        };
        let key = (event.host.as_str(), event.session_id.as_str(), action);
        match event.verdict {
            Verdict::Allow => {
                allowed_after.insert(key);
            }
            Verdict::Deny | Verdict::Review if allowed_after.contains(&key) => {
                found.insert(i);
            }
            _ => {}
        }
    }
    found
}

/// Counts as they are gathered, before the rates and percentiles.
#[derive(Debug, Default)]
struct Tally {
    figures: Figures,
    latencies: Vec<u64>,
}

impl Tally {
    fn add(&mut self, event: &Event, later_allowed: bool) {
        let f = &mut self.figures;
        f.calls += 1;
        let v = &mut f.verdicts;
        match event.verdict {
            Verdict::Allow => v.allow += 1,
            Verdict::Defer => v.defer += 1,
            Verdict::Review => v.review += 1,
            // `Deny`, and any verdict added to the core later: counted as the strictest.
            _ => v.deny += 1,
        }
        let has = |id: &str| event.rules.iter().any(|r| r == id);
        if event.verdict == Verdict::Allow && (has(APPROVED_SESSION) || has(APPROVED_REMOTE)) {
            f.approved += 1;
        }
        if later_allowed {
            if event.verdict == Verdict::Review {
                f.reviews_later_allowed += 1;
            } else {
                f.denies_later_allowed += 1;
            }
        }
        if has(KERNEL_ERROR) {
            f.kernel_errors += 1;
        }
        self.latencies
            .push(u64::try_from(event.latency_us).unwrap_or(0));
    }

    fn merge(&mut self, other: &Self) {
        let (f, o) = (&mut self.figures, &other.figures);
        f.calls += o.calls;
        f.verdicts.allow += o.verdicts.allow;
        f.verdicts.defer += o.verdicts.defer;
        f.verdicts.review += o.verdicts.review;
        f.verdicts.deny += o.verdicts.deny;
        f.approved += o.approved;
        f.denies_later_allowed += o.denies_later_allowed;
        f.reviews_later_allowed += o.reviews_later_allowed;
        f.kernel_errors += o.kernel_errors;
        f.guard_timeouts += o.guard_timeouts;
        self.latencies.extend_from_slice(&other.latencies);
    }

    fn finish(self) -> Figures {
        let mut f = self.figures;
        let (v, calls) = (f.verdicts, f.calls);
        f.per_100_calls = Verdicts {
            allow: per_100(v.allow, calls),
            defer: per_100(v.defer, calls),
            review: per_100(v.review, calls),
            deny: per_100(v.deny, calls),
        };
        f.latency = Latency::of(self.latencies);
        f
    }
}
