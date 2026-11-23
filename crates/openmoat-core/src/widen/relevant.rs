//! Which atoms the two policies can decide differently (ADR-111).
//!
//! Within one list the order of groups changes only the rule ids named, not
//! the verdict. So when both policies give an atom's kind the same default,
//! an atom no pattern matches that is in one policy and not in the same place
//! (list, group, kind, exclusion or not) of the other gets the same verdict
//! from both: deciding it cannot find a widening. The check decides only the
//! atoms some such pattern matches, which keeps it fast without skipping
//! anything that could widen.

use std::collections::BTreeSet;

use crate::action::AtomicAction;
use crate::engine::EvalContext;
use crate::kind::Kind;
use crate::pattern::{GlobPattern, ShellPattern};
use crate::policy::{Policy, PolicyError};

/// The patterns that differ, per kind, compiled for one context.
pub(super) struct Relevant<'p> {
    old: &'p Policy,
    new: &'p Policy,
    globs: Vec<(Kind, GlobPattern)>,
    shell: Vec<ShellPattern>,
}

/// Each pattern with its place: list, group id, kind and the text as written
/// (an exclusion keeps its `!`).
fn placed(policy: &Policy) -> BTreeSet<(&'static str, String, Kind, String)> {
    let lists = [
        ("deny", &policy.deny),
        ("repo", &policy.repo_review),
        ("allow", &policy.allow),
        ("review", &policy.review),
        ("defer", &policy.defer),
    ];
    let mut out = BTreeSet::new();
    for (list, groups) in lists {
        for g in groups {
            for kind in Kind::ALL {
                for p in g.patterns(kind) {
                    out.insert((list, g.id.clone(), kind, p.clone()));
                }
            }
        }
    }
    out
}

impl<'p> Relevant<'p> {
    pub(super) fn new(
        old: &'p Policy,
        new: &'p Policy,
        ctx: &EvalContext,
    ) -> Result<Self, PolicyError> {
        let (a, b) = (placed(old), placed(new));
        let mut globs = Vec::new();
        let mut shell = Vec::new();
        for (_, _, kind, raw) in a.symmetric_difference(&b) {
            let body = raw.strip_prefix('!').unwrap_or(raw);
            if *kind == Kind::Shell {
                shell.push(ShellPattern::compile(body)?);
                continue;
            }
            let case_insensitive = match kind {
                Kind::FsRead | Kind::FsWrite => ctx.case_insensitive_paths,
                Kind::Net | Kind::Fetch => true,
                _ => false,
            };
            for spelling in ctx.spellings(body) {
                globs.push((*kind, GlobPattern::compile(&spelling, case_insensitive)?));
            }
        }
        Ok(Self {
            old,
            new,
            globs,
            shell,
        })
    }

    /// Whether a shell pattern or a default differs: then the commands
    /// generated from shell rules are decided as whole calls too.
    pub(super) fn commands(&self) -> bool {
        !self.shell.is_empty()
            || self.old.defaults.unclassified() != self.new.defaults.unclassified()
            || Kind::ALL
                .iter()
                .any(|k| self.old.defaults.for_kind(*k).0 != self.new.defaults.for_kind(*k).0)
    }

    /// Whether the two policies may decide `atom` differently.
    pub(super) fn atom(&self, atom: &AtomicAction) -> bool {
        if self.old.defaults.for_atom(atom).0 != self.new.defaults.for_atom(atom).0 {
            return true;
        }
        match atom {
            AtomicAction::Shell { argv } | AtomicAction::Pipeline { argv } => {
                self.shell.iter().any(|p| p.is_match(argv))
            }
            _ => atom.subject().is_some_and(|subject| {
                let kinds = atom.kind().rule_kinds();
                self.globs
                    .iter()
                    .any(|(k, g)| kinds.contains(k) && g.is_match(subject))
            }),
        }
    }
}
