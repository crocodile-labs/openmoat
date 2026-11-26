//! Whether a policy change widens (ADR-111): every call, atom and setting
//! the new policy holds less strictly than the old one, on the verdict
//! lattice deny > review > defer > allow.
//!
//! [`compare`] decides both policies, in each evaluation context given, for
//!
//! - every case of the caller's corpus (conformance fixtures, `MoatBench` steps:
//!   [`fixtures`]), as whole calls;
//! - boundary cases generated from both policies' rules (`generate.rs`): each
//!   pattern's matches and near misses, each host and its lookalikes, each
//!   shell pattern's argument lists, each request rule's methods and paths,
//!   and one case per kind that only `defaults` decide. Patterns of rules
//!   that were removed or changed come from the old policy, so their edges
//!   are decided too;
//!
//! and searches symbolically (`proof.rs`) every subject of the kinds a glob
//! decides: file reads and writes, hosts, fetches, environment names and MCP
//! tools. For those kinds a search that ends is a proof, for that context,
//! that no subject's rule verdict moves toward allow; shell commands, request
//! rules and whole calls (with their folder, taint and request layers) are
//! checked over the cases only. [`Report::proof`] says which is which.
//! Settings outside the rules are compared one by one (`settings.rs`).

use std::collections::BTreeSet;

use serde::Serialize;

use crate::action::Action;
use crate::engine::{CompiledPolicy, EvalContext};
use crate::policy::{Policy, PolicyError};
use crate::requests::{RequestCheck, RequestRules};
use crate::verdict::Verdict;

mod corpus;
mod generate;
mod nfa;
mod proof;
mod relevant;
pub(crate) mod samples;
mod settings;

pub use corpus::{Case, Probe, WideningSource, fixtures};
pub use settings::{Change, Effect, RuleChange};

/// One case the new policy decides less strictly than the old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Widening {
    /// The call or atom, described (`read /Users/me/.ssh/id_rsa`).
    pub case: String,
    /// The fixture, rule or search it comes from.
    pub source: WideningSource,
    /// The old policy's verdict.
    pub before: Verdict,
    /// The rules that gave [`Self::before`].
    pub before_rules: Vec<String>,
    /// The new policy's verdict.
    pub after: Verdict,
    /// The rules that gave [`Self::after`].
    pub after_rules: Vec<String>,
}

impl Widening {
    fn new(
        case: String,
        source: WideningSource,
        (before, before_rules): (Verdict, Vec<String>),
        (after, after_rules): (Verdict, Vec<String>),
    ) -> Self {
        Self {
            case,
            source,
            before,
            before_rules,
            after,
            after_rules,
        }
    }
}

/// What the symbolic search concluded for one kind in one context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", content = "why", rename_all = "kebab-case")]
pub enum Outcome {
    /// No subject of the kind widens.
    Proven,
    /// The search found widenings, each confirmed by the engine.
    Widens,
    /// The search could not finish or found a case the engine did not
    /// confirm; the kind is checked over the cases only. Why.
    NotProven(String),
}

/// [`Outcome`] for one kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindProof {
    /// The kind (`fs.read`, `net`).
    pub kind: &'static str,
    /// The index of the evaluation context in the list [`compare`] was given.
    pub context: usize,
    /// What the search concluded.
    pub outcome: Outcome,
}

/// Everything [`compare`] found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// How many cases were decided under both policies, over all contexts.
    pub cases: usize,
    /// Every case that moves toward allow, once each.
    pub widenings: Vec<Widening>,
    /// Settings that changed, with their effect.
    pub settings: Vec<Change>,
    /// Rule groups and request entries added, removed, moved or changed.
    pub rules: Vec<RuleChange>,
    /// The symbolic search's result per kind and context.
    pub proof: Vec<KindProof>,
    /// What is checked over the cases only.
    pub sampled: Vec<&'static str>,
}

impl Report {
    /// Whether a case or a setting widens.
    #[must_use]
    pub fn widens(&self) -> bool {
        !self.widenings.is_empty() || self.settings.iter().any(|c| c.effect == Effect::Widens)
    }

    /// Whether a setting changed in a way not ranked, for a person to read.
    #[must_use]
    pub fn unchecked(&self) -> bool {
        self.settings.iter().any(|c| c.effect == Effect::Unchecked)
    }
}

/// What is checked over the cases only, never proven.
const SAMPLED: [&str; 3] = [
    "shell commands",
    "requests: rules",
    "whole calls (folders, taint, requests, pins)",
];

/// Decide `old` and `new` over `corpus`, the generated cases and the
/// symbolic search, in every context of `contexts`.
///
/// # Errors
/// When either policy does not compile for a context.
pub fn compare(
    old: &Policy,
    new: &Policy,
    contexts: &[EvalContext],
    corpus: &[Probe],
) -> Result<Report, PolicyError> {
    let mut report = Report {
        settings: settings::changes(old, new),
        rules: settings::rule_changes(old, new),
        sampled: SAMPLED.to_vec(),
        ..Report::default()
    };
    let mut found = Vec::new();
    for (index, ctx) in contexts.iter().enumerate() {
        let (was, now) = (
            CompiledPolicy::compile(old, ctx)?,
            CompiledPolicy::compile(new, ctx)?,
        );
        for target in proof::Target::ALL {
            let outcome = proof::search(&was, &now, target, &mut found);
            report.proof.push(KindProof {
                kind: target.name(),
                context: index,
                outcome,
            });
        }
        let relevant = relevant::Relevant::new(old, new, ctx)?;
        // Both policies share most rules: each case is decided once, an atom
        // only where a pattern that differs matches it (`relevant.rs`), and
        // whole calls in the first context: the corpus's, and the commands
        // generated from shell rules where a shell rule or a default differs.
        let mut seen = std::collections::HashSet::new();
        for probe in corpus.iter().chain(&generate::probes(old, new, ctx)) {
            let wanted = match &probe.case {
                Case::Atom(atom) => relevant.atom(atom),
                Case::Call(_) => {
                    index == 0
                        && (matches!(probe.source, WideningSource::Fixture(_))
                            || relevant.commands())
                }
            };
            if !wanted || !seen.insert(format!("{:?}", probe.case)) {
                continue;
            }
            report.cases += 1;
            let (before, after) = (decide(&was, &probe.case), decide(&now, &probe.case));
            if after.0 < before.0 {
                found.push(Widening::new(
                    describe(&probe.case),
                    probe.source.clone(),
                    before,
                    after,
                ));
            }
        }
    }
    report.cases += requests(old, new, &mut found)?;
    let mut seen = BTreeSet::new();
    found.retain(|w| seen.insert((w.case.clone(), w.before, w.after)));
    report.widenings = found;
    Ok(report)
}

/// The verdict and rules `policy` gives `case`; an atom no rule names (a
/// pipeline) counts as allowed: it adds nothing to a call.
fn decide(policy: &CompiledPolicy<'_>, case: &Case) -> (Verdict, Vec<String>) {
    let decision = match case {
        Case::Call(action) => Some(policy.decide(action)),
        Case::Atom(atom) => policy.evaluate_atomic(atom),
    };
    decision.map_or((Verdict::Allow, Vec::new()), |d| (d.verdict, d.rules))
}

/// Each generated request decided by both policies' request rules as the
/// hook holds them: refused is `deny`, passed is `allow`.
fn requests(old: &Policy, new: &Policy, found: &mut Vec<Widening>) -> Result<usize, PolicyError> {
    let (was, now) = (
        RequestRules::for_hook(&old.requests)?,
        RequestRules::for_hook(&new.requests)?,
    );
    let cases = generate::requests(old, new);
    let verdict = |rules: &RequestRules, r: &generate::Request| match rules.check(
        &r.host,
        &r.method,
        &r.target,
        &[],
    ) {
        RequestCheck::Refused(why) => (Verdict::Deny, vec![why]),
        _ => (Verdict::Allow, Vec::new()),
    };
    for r in &cases {
        let (before, after) = (verdict(&was, r), verdict(&now, r));
        if after.0 < before.0 {
            let case = format!("{} https://{}{}", r.method, r.host, r.target);
            found.push(Widening::new(
                case,
                WideningSource::Generated(r.source.clone()),
                before,
                after,
            ));
        }
    }
    Ok(cases.len())
}

/// A case in a line.
fn describe(case: &Case) -> String {
    match case {
        Case::Atom(atom) => atom.describe(),
        Case::Call(action) => match action {
            Action::Shell { command } => format!("shell \"{command}\""),
            Action::FsRead { path } => format!("read {path}"),
            Action::FsWrite { path } => format!("write {path}"),
            Action::Net { url } => format!("net {url}"),
            Action::Fetch { url } => format!("fetch {url}"),
            Action::WebSearch { query } => format!("web search \"{query}\""),
            Action::Patch { writes } => format!("patch {}", writes.join(", ")),
            other => format!("{other:?}"),
        },
    }
}

#[cfg(test)]
mod tests;
