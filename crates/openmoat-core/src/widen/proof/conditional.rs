//! Groups with `when` conditions in the search (ADR-113).
//!
//! Such a group matches no atom on its own; it adds its deny or review to a
//! whole call whose arguments meet its conditions, strictest winning
//! (`CompiledPolicy::with_arguments`). Arguments are not part of the subject
//! the search walks, so it bounds both sides: the old policy holds at most
//! what it would with every condition met (a deny group as a deny, a review
//! group as a review an allow cannot lift), the new policy at least what it
//! holds with none met (the group left out, as for an atom). A state where
//! the bounds cross is decided by the engine, which leaves the kind not
//! proven when it does not confirm it. A group both policies have alike (the
//! same list, patterns and conditions) adds the same to both and is left out
//! of both, so an unchanged condition does not stop a proof.

use std::collections::BTreeSet;

use crate::engine::{CompiledGroup, CompiledPolicy, Section};

/// Which policy a side of the search reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    /// The policy before the change: its verdicts are bounded from above.
    Old,
    /// The policy after it: its verdicts are bounded from below.
    New,
}

/// The `when` groups both policies have alike.
pub(super) struct Shared(BTreeSet<String>);

/// A `when` group as text: its list and everything compiled in it.
fn key(section: Section, group: &CompiledGroup) -> String {
    format!("{section:?} {group:?}")
}

/// Every `when` group of `policy`, as text.
fn conditional(policy: &CompiledPolicy<'_>) -> BTreeSet<String> {
    Section::ALL
        .iter()
        .flat_map(|s| {
            policy
                .section(*s)
                .iter()
                .filter(|g| g.conditional())
                .map(|g| key(*s, g))
        })
        .collect()
}

impl Shared {
    /// The `when` groups `old` and `new` have alike.
    pub(super) fn new(old: &CompiledPolicy<'_>, new: &CompiledPolicy<'_>) -> Self {
        Self(
            conditional(old)
                .intersection(&conditional(new))
                .cloned()
                .collect(),
        )
    }

    /// The list `group` of `section` is searched in for `role`, or `None`
    /// when the search leaves it out.
    pub(super) fn place(
        &self,
        role: Role,
        section: Section,
        group: &CompiledGroup,
    ) -> Option<Section> {
        if !group.conditional() {
            return Some(section);
        }
        if role == Role::New || self.0.contains(&key(section, group)) {
            return None;
        }
        Some(match section {
            Section::Deny => Section::Deny,
            // A repository review is held whatever the allow rules say, as
            // a met condition's review is.
            _ => Section::RepoReview,
        })
    }
}
