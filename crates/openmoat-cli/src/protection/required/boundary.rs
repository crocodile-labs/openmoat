//! Whether `require.run: full-boundary` (ADR-077) holds on this system, as
//! `openmoat status` and `openmoat doctor` report it. `openmoat run` makes the
//! same check when it starts and refuses; this is the reading ahead of that.

use openmoat_core::Policy;
use serde::Serialize;

use super::by;

/// The state of `require.run: full-boundary` here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Boundary {
    /// Which policy asks for it ([`by`]).
    pub by: String,
    /// Whether every part of it holds.
    pub met: bool,
    /// What does not hold, in words a person can act on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
}

impl Boundary {
    /// The state under `policy`, given what this system lacks (`system`,
    /// [`crate::commands::run_full_boundary_gap`]); `None` when nothing asks
    /// for it, so a policy without the setting reports nothing new.
    pub fn of(policy: &Policy, system: Option<String>) -> Option<Self> {
        let asked = policy.run_boundary_required()?;
        let gaps: Vec<String> = system.into_iter().collect();
        Some(Self {
            by: by(&asked),
            met: gaps.is_empty(),
            gaps,
        })
    }

    /// One line for a person: the requirement and whether it holds.
    pub fn describe(&self) -> String {
        let head = format!(
            "`openmoat run` must start with its full boundary ({})",
            self.by
        );
        if self.met {
            format!("{head}: holds on this system")
        } else {
            format!(
                "{head}: not met, so it refuses to start: {}",
                self.gaps.join("; ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> Policy {
        Policy::parse("version: 1\nrequire:\n  run: full-boundary\n").unwrap()
    }

    #[test]
    fn without_the_setting_nothing_is_reported() {
        let policy = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
        assert_eq!(Boundary::of(&policy, Some("no sandbox".into())), None);
    }

    #[test]
    fn it_holds_when_the_system_lacks_nothing() {
        let state = Boundary::of(&strict(), None).unwrap();
        assert!(state.met);
        assert!(state.describe().contains("holds on this system"));
        assert!(state.describe().contains("your policy"));
    }

    #[test]
    fn a_gap_is_named_and_not_met() {
        let state = Boundary::of(&strict(), Some("no bubblewrap".into())).unwrap();
        assert!(!state.met);
        assert!(state.describe().contains("no bubblewrap"), "{state:?}");
        assert!(state.describe().contains("refuses to start"), "{state:?}");
    }
}
