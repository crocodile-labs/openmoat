//! Where a rule group may say `hook_only: true` (ADR-034).

use super::{Policy, PolicyError, RuleGroup};

/// `hook_only` only narrows what OS layers deny, so it is valid on a `deny`
/// group that names files. An allow, ask or defer group lowered without its
/// paths would make an OS layer stricter for no reason, and a `net` or `fetch`
/// list left out would let every sandboxed command reach a host the hook denies.
pub(super) fn check(policy: &Policy) -> Result<(), PolicyError> {
    let others = policy.allow.iter().chain(&policy.ask).chain(&policy.defer);
    if let Some(group) = others.chain(&policy.repo_ask).find(|g| g.hook_only) {
        return Err(problem(group, "`hook_only` applies to `deny` groups only"));
    }
    for group in policy.deny.iter().filter(|g| g.hook_only) {
        if !group.net.is_empty() || !group.fetch.is_empty() {
            return Err(problem(
                group,
                "`hook_only` cannot apply to `net` or `fetch`: sandboxed commands would \
                 reach hosts the hook denies",
            ));
        }
        if group.fs_read.is_empty() && group.fs_write.is_empty() {
            return Err(problem(
                group,
                "`hook_only` needs `fs.read` or `fs.write` patterns; other kinds are \
                 applied by the hook only anyway",
            ));
        }
    }
    Ok(())
}

fn problem(group: &RuleGroup, problem: &str) -> PolicyError {
    PolicyError::Rule {
        rule: group.id.clone(),
        problem: problem.to_owned(),
    }
}
