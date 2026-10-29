//! A policy compiled for one context: the object every decision goes through.

use openmoat_core::{AtomicAction, CompiledPolicy, NoResolver, Taint};

use crate::action::Action;
use crate::context::Context;
use crate::decision::Decision;
use crate::error::Error;
use crate::facts::Facts;
use crate::policy::Policy;
use crate::session::Session;

/// A policy with every pattern compiled for one [`Context`].
///
/// Build one per policy and context and keep it: compiling dominates the cost
/// of a decision. Deciding takes `&self` and is deterministic: the same
/// policy, context, action, facts and session give the same decision.
#[derive(Debug)]
pub struct Engine {
    compiled: CompiledPolicy<'static>,
}

impl Engine {
    /// Compile `policy` for `context`.
    pub fn new(policy: Policy, context: &Context) -> Result<Self, Error> {
        let ctx = context.to_core()?;
        CompiledPolicy::compile_owned(policy.into_core(), &ctx)
            .map(|compiled| Self { compiled })
            .map_err(|e| Error::Context {
                message: e.to_string(),
            })
    }

    /// Decide `action` with no filesystem facts, in a fresh session.
    #[must_use]
    pub fn decide(&self, action: &Action) -> Decision {
        self.decide_with(action, &Facts::new(), &Session::new())
    }

    /// Decide `action` with what the caller observed (`facts`) and what earlier
    /// calls of the same session brought in (`session`). Never fails: input the
    /// engine cannot classify is `ask` or `defer` (rule `unparseable`), never
    /// `allow`.
    #[must_use]
    pub fn decide_with(&self, action: &Action, facts: &Facts, session: &Session) -> Decision {
        let action = action.to_core();
        let plain = self
            .compiled
            .decide_with(&action, facts.programs(), facts.paths());
        Decision::from_core(self.compiled.with_taint(
            plain,
            &action,
            facts.paths(),
            session.taint(),
        ))
    }

    /// The absolute paths `action` reads or writes, as the engine reads them
    /// (`cat ./a ~/b` names `<cwd>/a` and `<home>/b`), sorted and without
    /// repeats. Resolve each one's symlinks and report them in [`Facts::link`]
    /// before deciding, so a link cannot carry a call past a rule.
    #[must_use]
    pub fn paths(&self, action: &Action) -> Vec<String> {
        let (atoms, _) = self.compiled.atoms(&action.to_core(), &NoResolver);
        let mut paths: Vec<String> = atoms
            .into_iter()
            .filter_map(|atom| match atom {
                AtomicAction::FsRead { path } | AtomicAction::FsWrite { path } => Some(path),
                _ => None,
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// What running `action` exposed its session to ([`Session::record`]).
    pub(crate) fn exposure(&self, action: &Action, facts: &Facts) -> Taint {
        let cwd = self.compiled.context().cwd.clone();
        self.compiled
            .exposure(&action.to_core(), &cwd, facts.paths())
    }
}

#[cfg(test)]
mod tests;
