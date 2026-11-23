//! Which matchers can make the new policy decide a subject less strictly
//! than the old one: the search stops at a state where none of them can
//! still match (ADR-111).
//!
//! A pattern whose place differs between the policies is one of these
//! unless the change can only hold more: a pattern added to a deny group, or
//! to a review group while the kind's default is not `deny` (a review then
//! replaces only an allow by default, a defer or another review, never a
//! deny); an exclusion taken out of such a group; or an exclusion of such a
//! group the old policy does not have at all, which only narrows what the
//! new group holds. Everything else, allow and defer rules and repository
//! review included, is kept, so the stop is never earlier than a state
//! whose every continuation the old policy decides as strictly or less.

use std::collections::BTreeSet;

use super::{Section, Side};
use crate::verdict::Verdict;

/// One matcher in its place: section, group id, list, whether it excludes,
/// matcher index.
type Place = (usize, String, usize, bool, usize);

impl Side {
    /// Every matcher of every list, keyed by where it stands: section, group,
    /// list (bare lists after the others) and whether it excludes.
    fn placed(&self) -> BTreeSet<Place> {
        let mut out = BTreeSet::new();
        for (s, groups) in &self.sections {
            let section = Section::ALL.iter().position(|x| x == s).unwrap_or_default();
            for g in groups {
                for (n, list) in g.lists.iter().chain(g.bare.iter().flatten()).enumerate() {
                    for (neg, ms) in [(false, &list.pos), (true, &list.neg)] {
                        out.extend(ms.iter().map(|m| (section, g.id.clone(), n, neg, *m)));
                    }
                }
            }
        }
        out
    }

    /// The matchers of `self` (the old policy) and `new` whose change may
    /// lower a verdict: a subject none of them matches gets from `new` at
    /// least the old verdict, when the defaults agree. `None` when they do
    /// not: every subject may differ.
    pub(super) fn differing(&self, new: &Self) -> Option<BTreeSet<usize>> {
        if self.default != new.default {
            return None;
        }
        let (old_places, new_places) = (self.placed(), new.placed());
        let groups = |places: &BTreeSet<Place>| -> BTreeSet<(usize, String)> {
            places.iter().map(|(s, id, ..)| (*s, id.clone())).collect()
        };
        let (old_groups, new_groups) = (groups(&old_places), groups(&new_places));
        let holds = |section: usize| match Section::ALL.get(section) {
            Some(Section::Deny) => true,
            Some(Section::Review) => self.default <= Verdict::Review,
            _ => false,
        };
        // Only in the old policy: an exclusion gone from a group that holds
        // and that the new policy keeps makes the group hold more.
        let removed = old_places
            .difference(&new_places)
            .filter(|(s, id, _, neg, _)| {
                !(*neg && holds(*s) && new_groups.contains(&(*s, id.clone())))
            });
        // Only in the new policy: a pattern a holding group gains, or an
        // exclusion of a holding group the old policy has no group for.
        let added = new_places
            .difference(&old_places)
            .filter(|(s, id, _, neg, _)| {
                !(holds(*s) && (!*neg || !old_groups.contains(&(*s, id.clone()))))
            });
        Some(removed.chain(added).map(|(.., m)| *m).collect())
    }
}
