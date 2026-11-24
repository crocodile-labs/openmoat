//! The guard's deadline (ADR-120). Most agents run a call whose hook outlived
//! their time limit, so the guard answers deny on its own before it: at its
//! host's deadline ([`openmoat_hosts::HostSpec::guard_deadline_s`]), from a
//! thread that waits for nothing the decision path holds. Whatever blocks the
//! decision (the audit database's lock, a slow file system, a long session to
//! fold), the deny is written once, whole, in the host's own form, and the
//! process exits.
//!
//! One answer: every response goes through [`Gate::once`], which holds its
//! lock while the response is written, so the decision's answer and the
//! deadline's never interleave and the second is never written.

use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::Duration;

use openmoat_hosts::{HookEvent, Host};

/// Debug builds take the deadline from this variable, in milliseconds, so the
/// end-to-end tests reach it in a second rather than in 30. Release builds do
/// not read it.
#[cfg(debug_assertions)]
const DEADLINE_ENV: &str = "MOAT_TEST_GUARD_DEADLINE_MS";

/// When the guard of `host` stops deciding and denies on its own.
pub(super) fn of(host: Host) -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(DEADLINE_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(host.spec().guard_deadline_s())
}

/// Whether an answer was written; one per process.
pub(super) struct Gate(Mutex<bool>);

impl Gate {
    pub(super) const fn new() -> Self {
        Self(Mutex::new(false))
    }

    /// Run `write` unless an answer was written already, holding the gate
    /// while it runs: `None` when another answer came first.
    pub(super) fn once<T>(&self, write: impl FnOnce() -> T) -> Option<T> {
        let mut written = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if *written {
            return None;
        }
        *written = true;
        Some(write())
    }
}

/// The host the payload came from and its event, once read: the deadline's
/// deny is in their form (Copilot CLI's camel case, a settings-change veto),
/// not only the default event's.
static SEEN: OnceLock<(Host, HookEvent)> = OnceLock::new();

/// The payload was read: it is `host`'s, for `event`.
pub(super) fn saw(host: Host, event: &HookEvent) {
    let _ = SEEN.set((host, event.clone()));
}

/// What [`saw`] recorded, else `installed_for` and the default event.
pub(super) fn seen(installed_for: Host) -> (Host, HookEvent) {
    SEEN.get()
        .cloned()
        .unwrap_or_else(|| (installed_for, HookEvent::default()))
}

/// Run `fire` on a thread of its own once `after` has passed. The thread
/// shares nothing with the decision but the [`Gate`]; an error means it could
/// not be started, and the guard must not decide without it.
pub(super) fn arm(after: Duration, fire: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    thread::Builder::new()
        .name("openmoat-deadline".to_owned())
        .spawn(move || {
            thread::sleep(after);
            fire();
        })
        .map(drop)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{Gate, arm};

    /// A decision stuck past the deadline (here a sleep standing in for a
    /// held lock): the deadline's deny is written, whole and alone, within the
    /// deadline, and the decision's late answer is not written at all.
    #[test]
    fn a_stuck_decision_is_answered_by_the_deadline_once() {
        let gate = Arc::new(Gate::new());
        let out = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let deadline = Duration::from_millis(100);
        let started = Instant::now();
        let (fired, at) = mpsc::channel();
        let (g, o) = (Arc::clone(&gate), Arc::clone(&out));
        arm(deadline, move || {
            let wrote = g.once(|| writeln!(o.lock().unwrap(), "{{\"deny\":true}}").unwrap());
            fired.send((wrote.is_some(), started.elapsed())).unwrap();
        })
        .unwrap();
        // The decision path stays blocked until the deadline has answered.
        let (wrote, elapsed) = at.recv_timeout(Duration::from_secs(5)).unwrap();
        let late = gate.once(|| out.lock().unwrap().extend_from_slice(b"{\"allow\":true}\n"));
        assert!(wrote, "the deadline's deny was not written");
        // At the deadline, with room for a loaded machine's scheduling.
        assert!(
            elapsed >= deadline && elapsed < deadline + Duration::from_secs(2),
            "{elapsed:?}"
        );
        assert!(late.is_none(), "the late decision was written too");
        assert_eq!(*out.lock().unwrap(), b"{\"deny\":true}\n");
    }

    /// A decision in time: its answer stands, and the deadline writes nothing.
    #[test]
    fn a_decision_in_time_leaves_the_deadline_nothing_to_write() {
        let gate = Arc::new(Gate::new());
        let (fired, at) = mpsc::channel();
        let g = Arc::clone(&gate);
        arm(Duration::from_millis(50), move || {
            fired.send(g.once(|| ()).is_some()).unwrap();
        })
        .unwrap();
        assert!(gate.once(|| ()).is_some());
        assert!(!at.recv_timeout(Duration::from_secs(5)).unwrap());
    }

    /// The deadline's deny and a decision that finishes at the same moment:
    /// exactly one is written, never both and never a mix of the two.
    #[test]
    fn a_race_writes_one_whole_answer() {
        for _ in 0..50 {
            let gate = Arc::new(Gate::new());
            let out = Arc::new(std::sync::Mutex::new(String::new()));
            let (done, wait) = mpsc::channel();
            let (g, o) = (Arc::clone(&gate), Arc::clone(&out));
            arm(Duration::ZERO, move || {
                g.once(|| o.lock().unwrap().push_str("deny\n"));
                done.send(()).unwrap();
            })
            .unwrap();
            gate.once(|| out.lock().unwrap().push_str("allow\n"));
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            let written = out.lock().unwrap().clone();
            assert!(written == "deny\n" || written == "allow\n", "{written:?}");
        }
    }
}
