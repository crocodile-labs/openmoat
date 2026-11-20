//! Decoy keys in the conformance suite (ADR-106): a fixture's `decoys:` plants
//! them, and every other fixture is decided again with a standard set planted,
//! which must never loosen its verdict.

use openmoat_core::canary::Decoys;
use openmoat_core::{Action, CompiledPolicy, Decision, EvalContext, Policy};
use serde::Deserialize;

/// `decoys: { paths: [...], values: [...] }`: the decoys planted for the
/// fixture, as `canaries.json` lists them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Planted {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    values: Vec<String>,
}

impl Planted {
    fn decoys(&self) -> Decoys {
        Decoys {
            paths: self.paths.clone(),
            values: self.values.clone(),
        }
    }
}

/// `policy` with `planted`'s decoys guarded, as `openmoat guard` decides with
/// it; `None` without decoys.
pub fn guarded(policy: &Policy, planted: Option<&Planted>) -> Option<Policy> {
    let decoys = planted?.decoys();
    let mut policy = policy.clone();
    decoys.guard(&mut policy);
    Some(policy)
}

/// `decision` after the value check the guard runs last.
pub fn checked(planted: Option<&Planted>, action: &Action, decision: Decision) -> Decision {
    match planted {
        Some(planted) => planted.decoys().checked(action, decision),
        None => decision,
    }
}

/// The decoys `openmoat init` can plant, with values of no token shape.
fn standard() -> Decoys {
    Decoys {
        paths: vec![
            "~/.aws/credentials.bak".to_owned(),
            "~/.git-credentials.bak".to_owned(),
            "~/.npmrc.bak".to_owned(),
        ],
        values: vec!["OpenMoatDecoy-conformance-standard-0001".to_owned()],
    }
}

/// The default policy with the standard decoys, compiled for `ctx`.
pub fn standard_policy(policy: &Policy) -> Policy {
    let mut policy = policy.clone();
    standard().guard(&mut policy);
    policy
}

/// Panic when `guarded` (the policy with the standard decoys) decides
/// `action` more loosely than `plain` was decided without them.
pub fn never_widens(
    guarded: &CompiledPolicy<'_>,
    action: &Action,
    plain: &Decision,
    resolvers: (&openmoat_core::MapResolver, &openmoat_core::MapPathResolver),
    id: &str,
) {
    let with = standard().checked(
        action,
        guarded.decide_with(action, resolvers.0, resolvers.1),
    );
    assert!(
        with.verdict >= plain.verdict,
        "{id}: planting decoys loosened {:?} to {:?}",
        plain.verdict,
        with.verdict
    );
}

/// The context the shared policies compile for.
pub fn compile<'p>(policy: &'p Policy, ctx: &EvalContext) -> CompiledPolicy<'p> {
    CompiledPolicy::compile(policy, ctx).expect("default policy with decoys must compile")
}
