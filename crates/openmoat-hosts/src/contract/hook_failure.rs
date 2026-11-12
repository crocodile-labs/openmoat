//! What a host does with a tool call when OpenMoat's hook fails (ADR-079):
//! one typed fact per case, with the vendor documentation or source it comes
//! from. `moat doctor` reports a host that fails open from it, and
//! `docs/LIMITS.md` "If the hook fails" is generated from it (`tests/docs/`).

use super::Version;

/// What the host does with the call in one failure case. Exhaustive, so a new
/// kind fails to compile in the CLI until it says what to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    /// The host blocks the call, with OpenMoat's hook entry as `openmoat init`
    /// writes it.
    Blocks,
    /// The host blocks the call only when its entry carries the flag that asks
    /// for it, which the host reads from this version on; `openmoat init`
    /// writes the flag only when every copy of the host found is that version
    /// or later ([`HookSpec::block_on_failure`](crate::HookSpec)). Otherwise
    /// the call runs.
    BlocksFrom(Version),
    /// The host runs the call unchecked.
    Runs,
    /// The host's documentation does not say; OpenMoat assumes the call runs.
    NotDocumented,
}

impl FailureOutcome {
    /// The outcome in a few words, as the generated table and `doctor` say it.
    #[must_use]
    pub fn words(self) -> String {
        match self {
            Self::Blocks => "blocks the call".to_owned(),
            Self::BlocksFrom((major, minor, patch)) => format!(
                "blocks the call from {major}.{minor}.{patch} (`openmoat init` asks for it); \
                 runs it before"
            ),
            Self::Runs => "runs the call".to_owned(),
            Self::NotDocumented => "not documented; assumed to run the call".to_owned(),
        }
    }

    /// Whether the call may run with no decision: [`Self::Runs`] and
    /// [`Self::NotDocumented`]. [`Self::BlocksFrom`] depends on the version
    /// found, which only the CLI can ask, so it is not counted here.
    #[must_use]
    pub fn runs(self) -> bool {
        matches!(self, Self::Runs | Self::NotDocumented)
    }
}

/// What the host does when OpenMoat's hook fails, case by case: the hook
/// itself is OpenMoat's (it denies with exit 2 on every error it can catch,
/// ADR-004), so these are the failures it cannot catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookFailure {
    /// The hook command cannot start (the binary is gone), crashes, or exits
    /// non-zero without a decision the host reads.
    pub fails: FailureOutcome,
    /// The hook does not answer before the host's (or OpenMoat's plugin's)
    /// time limit.
    pub times_out: FailureOutcome,
    /// That time limit as `openmoat init` installs it, in seconds; `None` when
    /// the host documents none.
    pub timeout_s: Option<u32>,
    /// How a person, or a project, turns the hook off, so that every call runs
    /// with no check: the case no host can block, said for each.
    pub turned_off_by: &'static str,
    /// Where each fact comes from: the vendor's documentation, else its source
    /// at a named release, or a weekly real-agent run that observed what the
    /// vendor does not document. Empty only in [`Self::BASE`].
    pub sources: &'static [&'static str],
}

impl HookFailure {
    /// What a host spec starts from: nothing documented, no source; the
    /// registry's tests refuse it for every host.
    pub const BASE: Self = Self {
        fails: FailureOutcome::NotDocumented,
        times_out: FailureOutcome::NotDocumented,
        timeout_s: None,
        turned_off_by: "",
        sources: &[],
    };

    /// The cases in which the call runs with no decision, in words, from the
    /// facts alone ([`FailureOutcome::runs`]); empty for a host that blocks
    /// both. `blocks_from` says whether a [`FailureOutcome::BlocksFrom`] holds
    /// here, which only the CLI can tell.
    #[must_use]
    pub fn open_cases(&self, blocks_from: bool) -> Vec<&'static str> {
        let open = |outcome: FailureOutcome| match outcome {
            FailureOutcome::BlocksFrom(_) => !blocks_from,
            other => other.runs(),
        };
        let mut cases = Vec::new();
        if open(self.fails) {
            cases.push("cannot start, crashes or exits non-zero");
        }
        if open(self.times_out) {
            cases.push("times out");
        }
        cases
    }
}

#[cfg(test)]
mod tests {
    use super::{FailureOutcome, HookFailure};

    #[test]
    fn a_host_that_blocks_both_cases_has_no_open_case() {
        let blocks = HookFailure {
            fails: FailureOutcome::Blocks,
            times_out: FailureOutcome::Blocks,
            ..HookFailure::BASE
        };
        assert_eq!(blocks.open_cases(false), Vec::<&str>::new());
    }

    #[test]
    fn not_documented_counts_as_running_the_call() {
        assert_eq!(
            HookFailure::BASE.open_cases(true),
            ["cannot start, crashes or exits non-zero", "times out"]
        );
        assert!(FailureOutcome::NotDocumented.runs());
        assert!(!FailureOutcome::BlocksFrom((2, 1, 295)).runs());
    }

    #[test]
    fn blocks_from_is_open_only_where_the_version_does_not_read_the_flag() {
        let version_gated = HookFailure {
            fails: FailureOutcome::BlocksFrom((2, 1, 295)),
            times_out: FailureOutcome::Runs,
            ..HookFailure::BASE
        };
        assert_eq!(version_gated.open_cases(true), ["times out"]);
        assert_eq!(
            version_gated.open_cases(false),
            ["cannot start, crashes or exits non-zero", "times out"]
        );
        assert_eq!(
            FailureOutcome::BlocksFrom((2, 1, 295)).words(),
            "blocks the call from 2.1.295 (`openmoat init` asks for it); runs it before"
        );
    }
}
