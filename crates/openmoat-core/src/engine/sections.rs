//! A read-only view of a compiled policy's rule lists, for the never-widen
//! check (`widen/proof.rs`): it reads the globs the engine matches with, so
//! what it proves is about the patterns as the engine compiled them.

use super::{CompiledGroup, CompiledPolicy};
use crate::kind::Kind;
use crate::pattern::GlobPattern;

/// One of the lists [`CompiledPolicy::evaluate_atomic`] tries, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Deny,
    RepoReview,
    Allow,
    Review,
    Defer,
}

impl Section {
    /// Every list, in the order the engine tries them.
    pub(crate) const ALL: [Self; 5] = [
        Self::Deny,
        Self::RepoReview,
        Self::Allow,
        Self::Review,
        Self::Defer,
    ];
}

impl CompiledPolicy<'_> {
    /// The groups of one list.
    pub(crate) fn section(&self, section: Section) -> &[CompiledGroup] {
        match section {
            Section::Deny => &self.deny,
            Section::RepoReview => &self.repo_review,
            Section::Allow => &self.allow,
            Section::Review => &self.review,
            Section::Defer => &self.defer,
        }
    }
}

impl CompiledGroup {
    /// The group's id, as decisions name it.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The globs this group matches atoms of `kind` with (empty for `shell`).
    pub(crate) fn globs(&self, kind: Kind) -> &[GlobPattern] {
        &self.globs[kind as usize]
    }

    /// For an allow group, its `net` or `fetch` globs without the
    /// `host:port` ones, which a host without a port is matched against.
    pub(crate) fn bare_globs(&self, kind: Kind) -> Option<&[GlobPattern]> {
        self.bare_hosts
            .as_ref()
            .map(|b| b[kind as usize].as_slice())
    }

    /// Whether the group has `when` conditions (ADR-113): it matches no atom
    /// on its own, and adds its deny or review to a whole call whose
    /// arguments meet them ([`CompiledPolicy::with_arguments`]).
    pub(crate) fn conditional(&self) -> bool {
        self.when.is_some()
    }
}
