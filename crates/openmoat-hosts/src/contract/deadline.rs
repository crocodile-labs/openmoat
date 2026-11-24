//! When `openmoat guard` stops deciding and answers deny on its own for one
//! host (ADR-120): before the shortest hook time limit the host's spec gives,
//! so the deny reaches the host before its timer can fire. Most agents run a
//! call whose hook timed out; a deny that comes first is what they read.

use super::{GUARD_BUDGET_S, HostSpec};

/// Seconds the guard's deadline keeps below its host's shortest hook time
/// limit. After writing its deny the guard waits up to 2 s for its side-file
/// line, and a host reads the answer once the process ends; the rest covers
/// starting the process and waiting for a CPU on a loaded machine.
pub const DEADLINE_MARGIN_S: u64 = 5;

/// The shortest deadline a host may give the guard. A host whose own limit is
/// shorter would deny most calls on a loaded machine; the contract test keeps
/// every host above it, so a spec cannot drift there unseen.
pub const MIN_DEADLINE_S: u64 = 10;

/// The deadline for a host whose hook time limits are `limits` (seconds):
/// [`GUARD_BUDGET_S`], or the shortest limit less [`DEADLINE_MARGIN_S`] when
/// that comes first; never below 1 s, so the guard always gets to start.
#[must_use]
pub fn deadline_for(limits: impl IntoIterator<Item = u64>) -> u64 {
    limits
        .into_iter()
        .map(|limit| limit.saturating_sub(DEADLINE_MARGIN_S))
        .fold(GUARD_BUDGET_S, u64::min)
        .max(1)
}

impl HostSpec {
    /// Seconds after which `openmoat guard` answers this host with a deny on
    /// its own, rule `hook-deadline` (ADR-120): [`GUARD_BUDGET_S`], or less
    /// where one of the host's limits is shorter, the plugin callback time
    /// limit of [`super::HookFailure::timeout_s`] and each hook entry's
    /// [`super::HookSpec::timeout`] as `openmoat init` writes them.
    #[must_use]
    pub fn guard_deadline_s(&self) -> u64 {
        let failure = self.hook_failure.timeout_s.map(u64::from);
        let entries = self
            .install
            .iter()
            .flat_map(|install| install.hooks.iter().map(|hook| hook.timeout));
        deadline_for(failure.into_iter().chain(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEADLINE_MARGIN_S, GUARD_BUDGET_S, MIN_DEADLINE_S, deadline_for};
    use crate::{FailureOutcome, Host};

    #[test]
    fn the_budget_holds_where_every_limit_is_long_enough() {
        assert_eq!(deadline_for([600, 60]), GUARD_BUDGET_S);
        assert_eq!(deadline_for([]), GUARD_BUDGET_S);
        assert_eq!(
            deadline_for([GUARD_BUDGET_S + DEADLINE_MARGIN_S]),
            GUARD_BUDGET_S
        );
    }

    #[test]
    fn a_short_limit_brings_the_deadline_forward_by_the_margin() {
        assert_eq!(deadline_for([600, 30]), 25);
        assert_eq!(deadline_for([20]), 15);
        // A limit shorter than the margin still lets the guard start.
        assert_eq!(deadline_for([3]), 1);
    }

    /// Each host's deadline, from its spec: the guard's deny is written and
    /// its process gone before any limit the host was given fires.
    #[test]
    fn every_host_answers_before_each_of_its_limits() {
        for host in Host::EVERY {
            let spec = host.spec();
            let deadline = spec.guard_deadline_s();
            assert!(
                (MIN_DEADLINE_S..=GUARD_BUDGET_S).contains(&deadline),
                "{host:?}: {deadline} s"
            );
            let limits = spec
                .hook_failure
                .timeout_s
                .map(u64::from)
                .into_iter()
                .chain(
                    spec.install
                        .iter()
                        .flat_map(|i| i.hooks.iter().map(|h| h.timeout)),
                );
            for limit in limits {
                assert!(
                    deadline + DEADLINE_MARGIN_S <= limit,
                    "{host:?}: {deadline} s, {limit} s"
                );
            }
            // The guard's deny comes first only against a limit OpenMoat knows,
            // and only a timeout can be answered by it.
            let facts = &spec.hook_failure;
            if matches!(facts.times_out, FailureOutcome::GuardDenies(_)) {
                assert!(facts.timeout_s.is_some(), "{host:?}");
            }
            assert!(
                !matches!(facts.fails, FailureOutcome::GuardDenies(_)),
                "{host:?}"
            );
        }
    }

    /// The deadline is the budget unless one of the host's limits leaves less
    /// room, and then exactly that limit less the margin.
    #[test]
    fn each_host_s_deadline_is_its_budget_or_its_shortest_limit_less_the_margin() {
        for host in Host::EVERY {
            let spec = host.spec();
            let shortest = spec
                .hook_failure
                .timeout_s
                .map(u64::from)
                .into_iter()
                .chain(
                    spec.install
                        .iter()
                        .flat_map(|i| i.hooks.iter().map(|h| h.timeout)),
                )
                .min();
            let expected = match shortest {
                Some(limit) if limit < GUARD_BUDGET_S + DEADLINE_MARGIN_S => {
                    limit - DEADLINE_MARGIN_S
                }
                _ => GUARD_BUDGET_S,
            };
            assert_eq!(spec.guard_deadline_s(), expected, "{host:?}");
        }
    }
}
