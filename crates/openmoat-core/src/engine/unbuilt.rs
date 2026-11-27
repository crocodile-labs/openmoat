//! A glob built on first use that did not build (ADR-132).
//!
//! A compile builds a glob whose text cannot fail to parse only when a
//! candidate first needs its regex (`pattern/lazy.rs`). Should its build fail
//! anyway (a globset that parses differently), the glob answers "no match"
//! and sets the compile's mark. One glob can serve a deny list and an allow
//! list, so it cannot know which answer is strict for its list; instead every
//! decision of the compile from then on is the deny a compile error gives
//! (`kernel-error`, invariant 4). The checks here run inside the public
//! decision entry points, so every caller of the core gets that deny without
//! code of its own; `openmoat guard` also reads [`CompiledPolicy::unbuilt`]
//! after its session checks, which match globs outside them.

use std::borrow::Cow;
use std::sync::Arc;

use super::{CompiledPolicy, EvalContext};
use crate::pattern::{Built, Unbuilt};
use crate::policy::{Policy, PolicyError};
use crate::rule_id::KERNEL_ERROR;
use crate::verdict::{Decision, Verdict};

/// When a compile builds its globs. Not a stable API: [`CompiledPolicy::compile`]
/// always builds on first use, and the other modes are for tests that compare
/// them or that reach the failure mark.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobBuilds {
    /// Every glob when the policy is compiled.
    AtCompile,
    /// A glob whose text cannot fail to parse on its first use, the others
    /// when the policy is compiled: what [`CompiledPolicy::compile`] does.
    OnFirstUse,
    /// Every glob on its first use, so that a text that does not parse sets
    /// the failure mark instead of failing the compile.
    EveryOnFirstUse,
}

impl GlobBuilds {
    /// The glob store of a compile in this mode, with `mark` for its failures.
    pub(super) fn store(self, mark: &Arc<Unbuilt>) -> Built {
        match self {
            Self::AtCompile => Built::default(),
            Self::OnFirstUse => Built::deferring(mark),
            Self::EveryOnFirstUse => Built::deferring_every_text(mark),
        }
    }
}

impl CompiledPolicy<'_> {
    /// [`Self::compile_owned`] in another [`GlobBuilds`] mode. Not a stable
    /// API: for tests in this and other crates.
    #[doc(hidden)]
    pub fn compile_owned_building(
        policy: Policy,
        ctx: &EvalContext,
        builds: GlobBuilds,
    ) -> Result<CompiledPolicy<'static>, PolicyError> {
        CompiledPolicy::build(Cow::Owned(policy), ctx, builds)
    }

    /// Why a glob this compile built on first use did not build, in the words
    /// of the compile error it would have been: once set, every decision of
    /// this compile is the `kernel-error` deny.
    #[must_use]
    pub fn unbuilt(&self) -> Option<&str> {
        self.unbuilt.reason()
    }

    /// The `kernel-error` deny that replaces every decision once a glob did
    /// not build, with the reason `openmoat guard` gives a compile error.
    pub(super) fn failed(&self) -> Option<Decision> {
        self.unbuilt().map(|why| {
            Decision::single(
                Verdict::Deny,
                KERNEL_ERROR,
                format!("kernel could not evaluate this action: {why}"),
            )
        })
    }

    /// `decision`, or [`Self::failed`]'s deny once a glob did not build.
    pub(super) fn checked(&self, decision: Decision) -> Decision {
        self.failed().unwrap_or(decision)
    }
}

#[cfg(test)]
mod tests;
