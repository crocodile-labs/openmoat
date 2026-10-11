//! Lowering `policy.yaml` to the [`Enforcement`] IR.

use super::{
    Access, Allowance, BrokeredSecret, DecideOnly, Effect, Egress, Enforcement, Filesystem, Loss,
    Rule,
};
use crate::engine::{CompiledPolicy, EvalContext};
use crate::kind::Kind;
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::secret::Secret;
use crate::verdict::Verdict;

/// Id of the allowance `sandbox.read_roots` lowers to.
pub const READ_ROOTS_RULE: &str = "sandbox.read_roots";

/// Id of the deny rule every lowering adds to `net` and `fetch`.
pub const CLOUD_METADATA_RULE: &str = "moat.cloud-metadata";

/// Cloud instance-metadata and link-local hosts, which hand out credentials.
/// The egress proxy denies them by name whatever the policy says (ADR-020); the
/// default policy's `cloud-metadata` group lists the same hosts.
pub const CLOUD_METADATA: [&str; 6] = [
    "169.254.*",
    "fe80:*",
    "fd00:ec2::254",
    "100.100.100.200",
    "metadata.google.internal",
    "metadata.goog",
];

/// The kinds an OS layer can see; every other kind is decide-only.
const DECIDE_ONLY: [Kind; 5] = [
    Kind::Shell,
    Kind::WebSearch,
    Kind::EnvRead,
    Kind::EnvSet,
    Kind::Mcp,
];

/// Lower `policy` for `ctx` to what OS layers enforce.
///
/// Deterministic: rules follow policy order, patterns their written order with
/// each root spelling sorted. Fails exactly when [`CompiledPolicy::compile`]
/// fails, so the hook and every OS backend accept the same policies.
pub fn lower(policy: &Policy, ctx: &EvalContext) -> Result<Enforcement, PolicyError> {
    CompiledPolicy::compile(policy, ctx)?;
    let mut losses = Vec::new();
    let mut access = |kind| lower_access(policy, ctx, kind, &mut losses);
    let fs = Filesystem {
        case_insensitive: ctx.case_insensitive_paths,
        read: access(Kind::FsRead),
        write: access(Kind::FsWrite),
    };
    let mut egress = Egress {
        net: access(Kind::Net),
        fetch: access(Kind::Fetch),
    };
    for net in [&mut egress.net, &mut egress.fetch] {
        net.deny.push(Rule {
            id: CLOUD_METADATA_RULE.to_owned(),
            list: Kind::Net,
            patterns: CLOUD_METADATA.map(str::to_owned).to_vec(),
        });
    }
    Ok(Enforcement {
        fs,
        egress,
        secrets: policy.secrets.iter().map(lower_secret).collect(),
        limits: Vec::new(),
        decide_only: decide_only(policy),
        losses,
        allowances: read_roots(policy, ctx),
    })
}

/// Copy a policy [`Secret`] into the IR without the policy types.
fn lower_secret(secret: &Secret) -> BrokeredSecret {
    BrokeredSecret {
        id: secret.id.clone(),
        host: secret.host.clone(),
        header: secret.header.clone(),
        source: secret.source.clone(),
        plain_http: secret.plain_http,
    }
}

/// `sandbox.read_roots` as one allowance: each root and everything below it,
/// in every spelling of the home directory. Lint guarantees plain paths.
fn read_roots(policy: &Policy, ctx: &EvalContext) -> Vec<Allowance> {
    let patterns: Vec<String> = policy
        .sandbox
        .iter()
        .flat_map(|s| &s.read_roots)
        .flat_map(|root| {
            let root = root.trim_end_matches('/');
            [root.to_owned(), format!("{root}/**")]
        })
        .flat_map(|p| ctx.spellings(&p))
        .collect();
    if patterns.is_empty() {
        return Vec::new();
    }
    vec![Allowance {
        kind: Kind::FsRead,
        rule: READ_ROOTS_RULE.to_owned(),
        patterns,
        message: "the hook decides these reads by the rules (ask by default); OS layers allow \
                  them so commands can run, and deny rules still win"
            .to_owned(),
    }]
}

/// The engine's `deny → allow → ask → default` for one kind, with `ask` read as deny.
fn lower_access(policy: &Policy, ctx: &EvalContext, kind: Kind, losses: &mut Vec<Loss>) -> Access {
    let (verdict, default_rule) = policy.defaults.for_kind(kind);
    let default = if verdict == Verdict::Allow {
        Effect::Allow
    } else {
        Effect::Deny
    };
    if verdict == Verdict::Ask {
        losses.push(Loss {
            kind,
            rule: default_rule,
            message: "no rule matches: the hook asks, OS layers deny".to_owned(),
        });
    }
    let mut access = Access {
        default,
        deny: rules(&policy.deny, kind, ctx),
        allow: rules(&policy.allow, kind, ctx),
    };
    for rule in rules(&policy.ask, kind, ctx) {
        // Under a deny default an ask rule needs no rule of its own: what no allow
        // matches is denied anyway. Under an allow default it must deny, and an OS
        // layer has no tier between allow and the default, so it denies before
        // the allows do: narrower where an allow rule matches too.
        let message = match default {
            Effect::Deny => "the hook asks; OS layers deny unless an allow rule matches",
            Effect::Allow => "the hook asks; OS layers deny, also where an allow rule matches",
        };
        losses.push(Loss {
            kind,
            rule: rule.id.clone(),
            message: message.to_owned(),
        });
        if default == Effect::Allow {
            access.deny.push(rule);
        }
    }
    access
}

/// One rule per group and policy list that governs `kind`, patterns expanded as
/// the engine expands them. A rule whose patterns name no location (all
/// `${project}` without a project, or only exclusions) matches nothing in the
/// engine either, so it is left out.
fn rules(groups: &[RuleGroup], kind: Kind, ctx: &EvalContext) -> Vec<Rule> {
    groups
        .iter()
        .flat_map(|group| {
            kind.rule_kinds().iter().map(move |list| Rule {
                id: group.id.clone(),
                list: *list,
                patterns: group
                    .patterns(*list)
                    .iter()
                    .flat_map(|p| ctx.spellings(p))
                    .collect(),
            })
        })
        .filter(|rule| rule.patterns.iter().any(|p| !p.starts_with('!')))
        .collect()
}

fn decide_only(policy: &Policy) -> Vec<DecideOnly> {
    let groups = || policy.deny.iter().chain(&policy.allow).chain(&policy.ask);
    let mut out: Vec<DecideOnly> = DECIDE_ONLY
        .into_iter()
        .map(|kind| DecideOnly {
            kind: kind.as_str().to_owned(),
            rules: groups()
                .filter(|g| !g.patterns(kind).is_empty())
                .map(|g| g.id.clone())
                .collect(),
        })
        .filter(|d| !d.rules.is_empty())
        .collect();
    if !policy.executables.is_empty() {
        out.push(DecideOnly {
            kind: "executables".to_owned(),
            rules: policy.executables.keys().cloned().collect(),
        });
    }
    out
}
