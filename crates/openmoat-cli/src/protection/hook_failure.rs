//! What an agent does with a tool call when OpenMoat's hook fails (ADR-079),
//! from its [`HookFailure`] facts: `moat status --format json` carries them
//! per agent, and `moat status` and `moat doctor` name an agent that runs the
//! call then ("fails open") under its row, with what to do about it.

use openmoat_hosts::{FailureOutcome, HookFailure, Host};
use serde::Serialize;

/// What to do about an agent that fails open: the OS sandbox of `openmoat
/// run` holds whether or not the hook answers, and `require.run:
/// full-boundary` makes `openmoat run` refuse to start without all of it.
pub const FIX: &str = "start it with `openmoat run`, whose OS sandbox holds when the hook \
                       does not (docs/SANDBOX.md), and add `require.run: full-boundary` to the \
                       policy so `openmoat run` refuses to start without it";

/// One agent's hook-failure facts as they hold on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// The hook cannot start, crashes or exits non-zero: `blocks`, `runs` or
    /// `not-documented` (which OpenMoat takes as `runs`).
    pub fails: &'static str,
    /// The hook does not answer within [`Self::timeout_s`].
    pub times_out: &'static str,
    /// The time limit as `openmoat init` installs it, in seconds.
    pub timeout_s: Option<u32>,
    /// How the hook is turned off, when every call runs unchecked.
    pub turned_off_by: &'static str,
    /// The cases in which the call runs unchecked; empty when it never does.
    pub fails_open: Vec<&'static str>,
    /// The vendor documentation or source each fact comes from.
    pub sources: &'static [&'static str],
}

impl Failure {
    /// The row under the agent's for an agent that fails open; `None` for one
    /// that blocks in every case.
    pub fn line(&self) -> Option<String> {
        (!self.fails_open.is_empty()).then(|| {
            format!(
                "fails open: runs the call when the hook {}; {FIX}",
                self.fails_open.join(" or ")
            )
        })
    }
}

/// `host`'s facts, a [`FailureOutcome::BlocksFrom`] resolved by
/// `blocks_from`: whether every copy of the host found reads the flag that
/// asks for it, so that `openmoat init` wrote it.
pub fn of(host: Host, blocks_from: bool) -> Failure {
    let facts: &HookFailure = &host.spec().hook_failure;
    let word = |outcome: FailureOutcome| match outcome {
        FailureOutcome::Blocks => "blocks",
        FailureOutcome::BlocksFrom(_) if blocks_from => "blocks",
        FailureOutcome::BlocksFrom(_) | FailureOutcome::Runs => "runs",
        FailureOutcome::NotDocumented => "not-documented",
    };
    Failure {
        fails: word(facts.fails),
        times_out: word(facts.times_out),
        timeout_s: facts.timeout_s,
        turned_off_by: facts.turned_off_by,
        fails_open: facts.open_cases(blocks_from),
        sources: facts.sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every agent's facts resolve, and an agent that fails open says so with
    /// the way out; one that blocks in every case has no row.
    #[test]
    fn an_agent_that_fails_open_gets_a_row_with_the_fix() {
        for host in Host::EVERY {
            for blocks_from in [true, false] {
                let failure = of(host, blocks_from);
                if let Some(line) = failure.line() {
                    assert!(line.starts_with("fails open: runs the call when the hook "));
                    assert!(line.contains("`openmoat run`"), "{line}");
                    assert!(line.contains("require.run: full-boundary"), "{line}");
                } else {
                    assert_eq!(failure.fails, "blocks", "{host:?}");
                    assert_eq!(failure.times_out, "blocks", "{host:?}");
                }
            }
        }
    }

    /// An agent whose facts say it blocks only from a version reads as
    /// failing open where the version found does not read the flag.
    #[test]
    fn a_version_gated_block_holds_only_where_the_version_reads_it() {
        let gated = Host::EVERY
            .into_iter()
            .find(|h| matches!(h.spec().hook_failure.fails, FailureOutcome::BlocksFrom(_)));
        let Some(host) = gated else {
            return;
        };
        assert_eq!(of(host, true).fails, "blocks");
        assert_eq!(of(host, false).fails, "runs");
        assert!(of(host, false).line().is_some());
    }

    /// Not documented is reported as such, and counted as failing open.
    #[test]
    fn not_documented_fails_open() {
        for host in Host::EVERY {
            let failure = of(host, true);
            if failure.fails == "not-documented" {
                assert!(!failure.fails_open.is_empty(), "{host:?}");
            }
        }
    }
}
