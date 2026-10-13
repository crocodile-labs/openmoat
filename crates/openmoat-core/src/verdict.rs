//! The outcome of a policy decision.
//!
//! [`Verdict`] is `allow`, `defer`, `ask` or `deny`, ordered by strictness.
//! [`Decision`] is a verdict plus the rule ids and reasons that produced it.
//! When the atoms of one action are combined, the strictest verdict wins and
//! the weaker matches are kept as `context`, not dropped (docs/POLICY.md §4).

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Outcome of evaluating one or more atomic actions.
///
/// Ordering is by strictness: `Allow < Defer < Ask < Deny`. When several
/// atomic actions are combined, the strictest wins (docs/POLICY.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Verdict {
    /// The action may run.
    Allow,
    /// A person must decide; the host prompts or blocks.
    Ask,
    /// The action is blocked.
    Deny,
    /// No objection and no approval: the agent's own permission flow decides
    /// (ADR-025). Declared last so the other variants keep their discriminants.
    Defer,
}

impl Verdict {
    /// Position in the strictness order.
    fn strictness(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Defer => 1,
            Self::Ask => 2,
            Self::Deny => 3,
        }
    }
}

impl PartialOrd for Verdict {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Verdict {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.strictness().cmp(&other.strictness())
    }
}

impl Verdict {
    /// The lowercase name used in hook responses, the audit log and output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
            Self::Defer => "defer",
        }
    }
}

/// A name that is not `allow`, `defer`, `ask` or `deny`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown verdict `{0}`")]
pub struct UnknownVerdict(pub String);

impl FromStr for Verdict {
    type Err = UnknownVerdict;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Allow, Self::Defer, Self::Ask, Self::Deny]
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| UnknownVerdict(s.to_owned()))
    }
}

/// A verdict with the rule ids and human-readable reasons that produced it.
///
/// `rules`/`reasons` describe only the matches that carry the **final** verdict.
/// Matches with a weaker verdict (e.g. an `allow` on `git status` inside a command
/// that was denied for touching `~/.ssh`) are kept in `context` so the user still
/// sees the full picture without the headline being noisy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The strictest verdict across the matched rules.
    pub verdict: Verdict,
    /// Ids of the rule groups that produced `verdict`, in evaluation order, de-duplicated.
    pub rules: Vec<String>,
    /// One line per rule in `rules`.
    pub reasons: Vec<String>,
    /// Matches that did not determine the verdict (weaker outcomes), for display/audit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
}

impl Decision {
    /// A decision with no rules yet.
    #[must_use]
    pub fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            rules: Vec::new(),
            reasons: Vec::new(),
            context: Vec::new(),
        }
    }

    /// A decision produced by one rule for one reason.
    #[must_use]
    pub fn single(verdict: Verdict, rule: &str, reason: impl Into<String>) -> Self {
        let mut decision = Self::new(verdict);
        decision.push(rule, reason.into());
        decision
    }

    pub(crate) fn push(&mut self, rule: &str, reason: String) {
        if !self.rules.iter().any(|r| r == rule) {
            self.rules.push(rule.to_owned());
        }
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    /// Merge another decision in: strictest verdict wins; matches of the losing
    /// side are demoted to `context`.
    pub(crate) fn merge(&mut self, other: Decision) {
        if other.verdict > self.verdict {
            let demoted: Vec<String> = self.reasons.drain(..).collect();
            self.rules.clear();
            self.context.extend(demoted);
            self.verdict = other.verdict;
        } else if other.verdict < self.verdict {
            self.context.extend(other.reasons);
            self.context.extend(other.context);
            return;
        }
        for (r, why) in other.rules.into_iter().zip(other.reasons) {
            self.push(&r, why);
        }
        self.context.extend(other.context);
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, UnknownVerdict, Verdict};

    #[test]
    fn verdict_names_round_trip() {
        for v in [Verdict::Allow, Verdict::Defer, Verdict::Ask, Verdict::Deny] {
            assert_eq!(v.as_str().parse::<Verdict>(), Ok(v));
        }
        assert_eq!(
            "block".parse::<Verdict>(),
            Err(UnknownVerdict("block".into()))
        );
    }

    #[test]
    fn single_carries_one_rule_and_reason() {
        let d = Decision::single(Verdict::Deny, "kernel-error", "no lock");
        assert_eq!(d.rules, ["kernel-error"]);
        assert_eq!(d.reasons, ["no lock"]);
        assert!(d.context.is_empty());
    }

    fn decided(verdict: Verdict, rule: &str) -> Decision {
        let mut d = Decision::new(verdict);
        d.push(rule, format!("because {rule}"));
        d
    }

    #[test]
    fn stricter_verdict_replaces_and_demotes_the_weaker_match() {
        let mut d = decided(Verdict::Allow, "project-fs");
        d.merge(decided(Verdict::Deny, "secrets-paths"));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["secrets-paths"]);
        assert_eq!(d.reasons, ["because secrets-paths"]);
        assert_eq!(d.context, ["because project-fs"]);
    }

    #[test]
    fn weaker_verdict_only_adds_context() {
        let mut d = decided(Verdict::Deny, "secrets-paths");
        d.merge(decided(Verdict::Allow, "dev-shell"));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["secrets-paths"]);
        assert_eq!(d.context, ["because dev-shell"]);
    }

    #[test]
    fn equal_verdicts_union_rules_without_duplicates() {
        let mut d = decided(Verdict::Ask, "installs");
        d.merge(decided(Verdict::Ask, "installs"));
        d.merge(decided(Verdict::Ask, "push"));
        assert_eq!(d.rules, ["installs", "push"]);
        assert_eq!(d.reasons.len(), 2);
        assert!(d.context.is_empty());
    }

    #[test]
    fn verdict_order_is_allow_defer_ask_deny() {
        assert!(Verdict::Allow < Verdict::Defer);
        assert!(Verdict::Defer < Verdict::Ask && Verdict::Ask < Verdict::Deny);
    }
}
