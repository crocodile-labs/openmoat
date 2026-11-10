//! Whether `require.run: full-boundary` (ADR-077) holds on this system, as
//! `openmoat status` and `openmoat doctor` report it. `openmoat run` makes the
//! system's half of the same check when it starts and refuses; the MCP half
//! can only be reported, because the agent starts its servers itself.

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
    /// What this system lacks, for which `openmoat run` refuses to start.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
    /// Local MCP servers left unprotected, which fail the requirement but
    /// which nothing can refuse: the agent starts them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mcp: Vec<String>,
}

impl Boundary {
    /// The state under `policy`, given what this system lacks (`system`,
    /// [`crate::commands::run_full_boundary_gap`]) and the unprotected MCP
    /// servers (`mcp`, only read when something asks for it); `None` when
    /// nothing asks, so a policy without the setting reports nothing new.
    pub fn of(
        policy: &Policy,
        system: Option<String>,
        mcp: impl FnOnce() -> Vec<String>,
    ) -> Option<Self> {
        let asked = policy.run_boundary_required()?;
        let gaps: Vec<String> = system.into_iter().collect();
        let mcp = mcp();
        Some(Self {
            by: by(&asked),
            met: gaps.is_empty() && mcp.is_empty(),
            gaps,
            mcp,
        })
    }

    /// One line for a person: the requirement, and what does not hold.
    pub fn describe(&self) -> String {
        let head = format!(
            "`openmoat run` must start with its full boundary ({})",
            self.by
        );
        if self.met {
            return format!("{head}: holds on this system");
        }
        let mut parts = Vec::new();
        if !self.gaps.is_empty() {
            parts.push(format!("it refuses to start: {}", self.gaps.join("; ")));
        }
        if !self.mcp.is_empty() {
            parts.push(format!(
                "MCP servers the agent starts itself, which `openmoat run` cannot refuse: {}",
                self.mcp.join("; ")
            ));
        }
        format!("{head}: not met: {}", parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> Policy {
        Policy::parse("version: 1\nrequire:\n  run: full-boundary\n").unwrap()
    }

    #[test]
    fn without_the_setting_nothing_is_reported_or_read() {
        let policy = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
        let state = Boundary::of(&policy, Some("no sandbox".into()), || {
            panic!("the MCP servers are not read without the setting")
        });
        assert_eq!(state, None);
    }

    #[test]
    fn it_holds_when_nothing_is_missing() {
        let state = Boundary::of(&strict(), None, Vec::new).unwrap();
        assert!(state.met);
        assert!(state.describe().contains("holds on this system"));
        assert!(state.describe().contains("your policy"));
    }

    #[test]
    fn a_system_gap_is_named_and_says_the_run_refuses() {
        let state = Boundary::of(&strict(), Some("no bubblewrap".into()), Vec::new).unwrap();
        assert!(!state.met);
        assert!(state.describe().contains("no bubblewrap"), "{state:?}");
        assert!(state.describe().contains("refuses to start"), "{state:?}");
    }

    /// An unprotected server fails the requirement, and the line does not
    /// claim the run refuses for it.
    #[test]
    fn an_unprotected_server_fails_without_claiming_a_refusal() {
        let state = Boundary::of(&strict(), None, || vec!["`gh`: unprotected".to_owned()]).unwrap();
        assert!(!state.met);
        let line = state.describe();
        assert!(line.contains("`gh`: unprotected"), "{line}");
        assert!(line.contains("cannot refuse"), "{line}");
        assert!(!line.contains("it refuses to start"), "{line}");
    }
}
