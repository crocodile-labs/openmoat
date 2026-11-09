//! How `openmoat run` keeps its relay token from a host's tool commands
//! (ADR-075, which holds the source of each host's fact).

/// How the host starts its tool commands, as far as the run can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolToken {
    /// The run has no way to separate this host's tool commands from its
    /// hooks, or none that was confirmed: they keep the token.
    NotWithheld {
        /// Why, in a few words, as `moat doctor` shows it.
        why: &'static str,
    },
    /// The host picks its tool shell from these variables, and starts its
    /// hooks without it: the run points them at a wrapper that drops the
    /// token before the shell starts.
    Wrapper {
        /// Variables set to the wrapper for the agent.
        vars: &'static [&'static str],
        /// Whether the host finds its shell on `PATH` (the wrapper's directory
        /// goes first).
        on_path: bool,
    },
    /// The host's hook runs inside its own process, which takes the token out
    /// of the environment later children copy (`host/<module>/integration/`).
    Integration,
}

impl ToolToken {
    /// What a host starts from.
    pub const BASE: Self = Self::NotWithheld {
        why: "not checked for this host",
    };

    /// Whether tool commands of this host do not receive the token.
    #[must_use]
    pub fn withheld(self) -> bool {
        !matches!(self, Self::NotWithheld { .. })
    }
}
