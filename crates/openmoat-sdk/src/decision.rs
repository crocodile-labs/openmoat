//! What the engine says about one tool call.

use std::fmt;

use serde::{Deserialize, Serialize};

use openmoat_core::{Decision as CoreDecision, Verdict as CoreVerdict};

/// The outcome of a decision, ordered by strictness:
/// `Allow < Defer < Review < Deny`.
///
/// | Verdict | The caller |
/// |---|---|
/// | `Deny` | must not run the call; no approval can lift it |
/// | `Review` | runs it only after a person approves this exact call |
/// | `Defer` | applies its own permission flow; OpenMoat neither objects nor vouches |
/// | `Allow` | may run it |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Verdict {
    /// The call may run.
    Allow,
    /// No objection and no approval: the caller's own permission flow decides.
    Defer,
    /// A person must approve this exact call before it runs. Read from `"ask"`,
    /// its name before 0.14.0 (ADR-053), so a caller or log written then still
    /// decodes; only `"review"` is written.
    #[serde(alias = "ask")]
    Review,
    /// The call must not run.
    Deny,
}

impl Verdict {
    /// The lowercase name: `allow`, `defer`, `review` or `deny`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Defer => "defer",
            Self::Review => "review",
            Self::Deny => "deny",
        }
    }

    /// The SDK verdict for the engine's. A verdict this release does not know
    /// is a deny, never a pass.
    pub(crate) fn from_core(verdict: CoreVerdict) -> Self {
        match verdict {
            CoreVerdict::Allow => Self::Allow,
            CoreVerdict::Defer => Self::Defer,
            CoreVerdict::Review => Self::Review,
            _ => Self::Deny,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verdict with the rule ids and reasons that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Decision {
    /// The strictest verdict across everything the call does.
    pub verdict: Verdict,
    /// The ids of the rules that produced `verdict`, in evaluation order,
    /// without repeats (`secrets-paths`, `default.net`, `unparseable`). Stable:
    /// the same ids the `openmoat` CLI records in its audit log.
    pub rules: Vec<String>,
    /// One human-readable line per match that produced `verdict`.
    pub reasons: Vec<String>,
    /// Weaker matches that did not decide (an `allow` of `git` inside a command
    /// denied for reading `~/.ssh`), for display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
}

impl Decision {
    /// `reasons` as one line, for a message to the agent or a person.
    #[must_use]
    pub fn reason(&self) -> String {
        self.reasons.join("; ")
    }

    pub(crate) fn from_core(decision: CoreDecision) -> Self {
        Self {
            verdict: Verdict::from_core(decision.verdict),
            rules: decision.rules,
            reasons: decision.reasons,
            context: decision.context,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreDecision, CoreVerdict, Decision, Verdict};

    #[test]
    fn verdicts_keep_the_engine_order_and_names() {
        let all = [
            Verdict::Allow,
            Verdict::Defer,
            Verdict::Review,
            Verdict::Deny,
        ];
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        for (v, core) in all.into_iter().zip([
            CoreVerdict::Allow,
            CoreVerdict::Defer,
            CoreVerdict::Review,
            CoreVerdict::Deny,
        ]) {
            assert_eq!(Verdict::from_core(core), v);
            assert_eq!(v.as_str(), core.as_str());
            assert_eq!(v.to_string(), core.as_str());
        }
    }

    /// ADR-053: JSON from a caller or a log written before 0.14.0 says `"ask"`.
    #[test]
    fn the_old_name_ask_reads_as_review() {
        let old: Verdict = serde_json::from_str("\"ask\"").unwrap();
        assert_eq!(old, Verdict::Review);
        assert_eq!(serde_json::to_string(&old).unwrap(), "\"review\"");
    }

    #[test]
    fn reason_joins_the_reasons() {
        let mut core = CoreDecision::single(CoreVerdict::Review, "a", "one");
        core.reasons.push("two".into());
        let d = Decision::from_core(core);
        assert_eq!(d.reason(), "one; two");
        assert_eq!(d.rules, ["a"]);
    }
}
