//! Holding the hook for an approver's answer (ADR-093). A call held for
//! review that was sent for approval, while `openmoat approvals listen` runs
//! ([`super::live`]), waits a bounded time in the guard: an approval that
//! arrives meanwhile is used for this call, a deny denies it, and nothing in
//! time leaves the `review` exactly as without the wait.
//!
//! How long is the least of three limits: the person's own setting
//! ([`super::Settings::wait`], [`DEFAULT_WAIT_S`]); the guard's budget
//! ([`GUARD_BUDGET_S`], after which it denies on its own) less the time it
//! keeps to record and answer ([`ANSWER_MARGIN`]) and, under `openmoat run`,
//! the relay's own share ([`RELAY_MARGIN`]); and the host's hook timeout from
//! its spec ([`host_limit`]), of which a host that runs a call whose hook
//! timed out gives only a [`FAIL_OPEN_SHARE`]th.

use std::time::{Duration, Instant};

use anyhow::Result;
use openmoat_core::Decision;
use openmoat_hosts::{FailureOutcome, GUARD_BUDGET_S, HookFailure};

use super::request::Request;
use super::settings::Settings;
use super::store::Store;
use crate::hangs::{self, Phase};
use crate::proxy_session::Key;

/// How long the hook waits unless the person chose otherwise.
pub const DEFAULT_WAIT_S: u64 = 20;
/// What the guard keeps of its budget after the wait, to record the call and
/// answer the host on a loaded machine.
pub const ANSWER_MARGIN: Duration = Duration::from_secs(5);
/// What a guard `openmoat run` started outside its sandbox keeps on top: the
/// guard inside, which the host waits for, started earlier and counts its own
/// budget from then.
pub const RELAY_MARGIN: Duration = Duration::from_secs(5);
/// The longest wait a person can set: the guard's budget less
/// [`ANSWER_MARGIN`]. Each call gets less when it started late or its host
/// allows less.
pub const MAX_WAIT_S: u64 = GUARD_BUDGET_S - ANSWER_MARGIN.as_secs();
const _: () = assert!(DEFAULT_WAIT_S <= MAX_WAIT_S);
/// A host that runs a call whose hook timed out (or whose documentation does
/// not say) is held for at most this fraction of its timeout, so the wait is
/// far below the point where the call would run unchecked.
pub const FAIL_OPEN_SHARE: u32 = 4;
/// How often the guard looks for the answer file.
const STEP: Duration = Duration::from_millis(100);
/// How often it checks the listener still runs.
const LIVE_EVERY: Duration = Duration::from_secs(1);

/// How long the host lets the hook run, as far as waiting is concerned, from
/// its spec's hook-failure facts: all of its timeout where a timed-out hook
/// blocks the call, a [`FAIL_OPEN_SHARE`]th where the call might run, and
/// nothing where no timeout is documented. A [`FailureOutcome::BlocksFrom`]
/// counts as running: which version is installed is not checked per call.
pub fn host_limit(failure: &HookFailure) -> Duration {
    let Some(timeout) = failure.timeout_s else {
        return Duration::ZERO;
    };
    let timeout = Duration::from_secs(u64::from(timeout));
    match failure.times_out {
        FailureOutcome::Blocks => timeout,
        FailureOutcome::BlocksFrom(_)
        | FailureOutcome::BlocksWhenMissing
        | FailureOutcome::Runs
        | FailureOutcome::NotDocumented => timeout / FAIL_OPEN_SHARE,
    }
}

/// How much longer a guard that has run `elapsed` may wait for an answer on
/// a host with `failure`'s facts; `relayed`: `openmoat run` started it. The
/// guard's whole run then ends [`ANSWER_MARGIN`] (and [`RELAY_MARGIN`])
/// before the smaller of its budget and [`host_limit`].
pub fn room(failure: &HookFailure, elapsed: Duration, relayed: bool) -> Duration {
    let end = host_limit(failure).min(Duration::from_secs(GUARD_BUDGET_S));
    let margin = if relayed {
        ANSWER_MARGIN + RELAY_MARGIN
    } else {
        ANSWER_MARGIN
    };
    end.saturating_sub(margin).saturating_sub(elapsed)
}

/// When the gate must stop waiting for this call (now plus [`room`], fixed
/// before the gate starts), and the clock the listener's beat and the
/// request's expiry are read against.
pub struct Hold<'a> {
    pub until: Instant,
    pub clock: &'a dyn Fn() -> i64,
}

#[cfg(test)]
impl Hold<'static> {
    /// No wait at all.
    pub fn none() -> Self {
        Self {
            until: Instant::now(),
            clock: &crate::time::now_ms,
        }
    }
}

/// How a wait ended.
#[derive(Debug)]
pub enum Waited {
    /// No wait: no room, the person turned it off, or no listener runs.
    Not,
    /// Nothing usable came within the wait, which lasted this long.
    NoAnswer(Duration),
    /// An answer came after this long: the decision it gives, and the request
    /// whose approval the call used, if one was.
    Answered(Box<(Decision, Option<Request>)>, Duration),
    /// Another guard (a retry of the same call) used the approval: the
    /// review, saying so.
    Taken(Box<Decision>),
}

/// Wait for an answer to `open`, which holds `held`, within `hold`, while the
/// listener of `settings`' channel runs. The answer is checked by
/// [`super::gate::answered`], as on the next try, against the settings as
/// they read when it arrives.
pub fn hold(
    store: &Store,
    key: &Key,
    settings: &Settings,
    (open, held): (&Request, &Decision),
    limits: &Hold<'_>,
) -> Result<Waited> {
    let started = Instant::now();
    let until = limits.until.min(started + settings.wait());
    if until <= started || !super::live::live(store, key, &settings.channel, (limits.clock)()) {
        return Ok(Waited::Not);
    }
    hangs::enter(Phase::Approval);
    let mut seen_live = started;
    loop {
        // Another guard (a retry of the same call) used the approval.
        if store.used(&open.id) {
            let mut kept = held.clone();
            kept.reasons.push(format!(
                "request {} was approved once and is used",
                open.code()
            ));
            return Ok(Waited::Taken(Box::new(kept)));
        }
        if store.has_answer(&open.id) {
            // As the guard reads them now: an approver removed meanwhile no
            // longer counts.
            let now = Settings::load(&store.settings_path(), key)?;
            if let Some((decided, used)) = super::gate::answered(store, key, &now, open, held)? {
                return Ok(Waited::Answered(
                    Box::new((decided, used)),
                    started.elapsed(),
                ));
            }
        }
        let now = Instant::now();
        if now >= until || open.expired((limits.clock)()) {
            break;
        }
        if seen_live.elapsed() >= LIVE_EVERY {
            if !super::live::live(store, key, &settings.channel, (limits.clock)()) {
                break;
            }
            seen_live = Instant::now();
        }
        std::thread::sleep(STEP.min(until.saturating_duration_since(now)));
    }
    Ok(Waited::NoAnswer(started.elapsed()))
}
