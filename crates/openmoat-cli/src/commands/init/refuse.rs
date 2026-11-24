//! What `init` refuses before it writes anything: a re-pin its checks do not
//! allow, and a binary an agent could replace.

use std::io::Write as _;

use anyhow::{Result, bail};
use openmoat_core::rule_id::KERNEL_INTEGRITY;
use openmoat_core::{DEFAULT_POLICY, Policy};

use super::repin_checks;
use crate::home::Home;
use crate::integrity;
use crate::render::Deferred;
use crate::sandbox::Plan;

/// Refuse, before anything is written, a re-pin [`repin_checks`] does not
/// allow; returns whether a lock exists. An unreadable lock counts as drift:
/// `init` at a terminal is how a person recovers from one, and without a
/// terminal it is refused like any other drift.
pub(super) fn refuse_repin(home: &Home, out: &mut Deferred) -> Result<bool> {
    let lock_path = home.lock_path();
    let lock_exists = lock_path.exists();
    let checks = repin_checks(lock_exists, crate::terminal::interactive());
    let drift: Vec<String> = if lock_exists {
        integrity::Lock::load(&lock_path).map_or_else(
            |error| vec![format!("{} cannot be read: {error:#}", lock_path.display())],
            |lock| lock.verify().iter().map(ToString::to_string).collect(),
        )
    } else {
        Vec::new()
    };
    if checks.drift && !drift.is_empty() {
        bail!(
            "refusing to re-pin while the policy lock shows drift ({}) and no person is at \
             a terminal:\n  {}\nrun `openmoat doctor` to see what changed, then `openmoat doctor \
             --accept` in a terminal of your own if the changes are yours",
            KERNEL_INTEGRITY,
            drift.join("\n  ")
        );
    }
    if checks.agent {
        crate::terminal::refuse_agent("openmoat init")?;
    }
    // Re-pinning over drift accepts every changed file, and a lock gone while
    // the gate is on is one taken away: either asks the gate (ADR-117). A
    // first `init`, and one over an intact lock, ask nothing.
    if !drift.is_empty() || (!lock_exists && crate::gate::enrolled(home)) {
        let what = if lock_exists {
            "lock re-pinned over drift"
        } else {
            "lock made again while the gate is on"
        };
        crate::gate::pass(home, "openmoat init")?.record(home, what, &drift);
    }
    if !drift.is_empty() {
        writeln!(
            out,
            "! lock drift       re-pinning over: {}",
            drift.join("; ")
        )?;
    }
    Ok(lock_exists)
}

/// Refuse, before anything is written, a binary an agent could replace; the
/// sandboxes' writable directories come from the policy `init` will apply.
pub(super) fn refuse_writable_binary(home: &Home, binary: &std::path::Path) -> Result<()> {
    let policy = if home.policy_path().exists() {
        home.load_policy()
    } else {
        Ok(Policy::parse(DEFAULT_POLICY)?)
    };
    // A policy that does not lint is reported by `sandboxes`, which then
    // writes no sandbox, so there are no sandbox grants to check.
    let writable = policy
        .and_then(|p| Plan::for_binary(home, &p, binary))
        .map(|plan| plan.writable_dirs())
        .unwrap_or_default();
    crate::install::self_paths::refuse_writable(binary, &writable)
}
