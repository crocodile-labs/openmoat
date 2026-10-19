//! Claude Code's `ConfigChange` hook: whether a settings file that changed on
//! disk may load into the running session.

use anyhow::{Result, bail};
use openmoat_core::{Decision, Verdict};

use crate::home::Home;
use crate::integrity::{self, Drift, INTEGRITY_RULE, Lock};

const CONFIG_CHANGE_RULE: &str = "config-change";

/// A settings file changed on disk. While a pinned file drifted beyond the
/// settings `integrity/relaxed.rs` lets the guard decide through, no change is
/// loaded: the session keeps the old settings and the drift is reported.
/// Otherwise a pinned file loads (it matches the lock, or differs only in those
/// settings), a settings-review copy of one loads only if it leaves the pinned
/// file as is, and an unpinned file is audited and allowed.
pub(super) fn decision(
    home: &Home,
    action: Option<&openmoat_core::Action>,
    source: &str,
    change: &str,
) -> Result<Decision> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let lock = Lock::load(&lock_path)?;
    // Checked whatever file the change names: settings load together, so an
    // unpinned file's change would also load a tampered pinned one (every tool
    // call is denied then anyway). Drift the guard decides through loads: it
    // changes Claude Code's own toggles and asks, never a hook.
    let drift = lock.verify();
    let relaxed = !drift.is_empty();
    if relaxed && integrity::split(home, &lock, drift.clone()).deny.is_some() {
        return Ok(drift_blocks_change(&drift));
    }
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
    let path = match action {
        Some(openmoat_core::Action::FsWrite { path }) => std::path::Path::new(path),
        Some(_) => bail!("config change for something other than a file"),
        // Claude Code may report a change without naming the file. Every pin
        // matches, and refusing the change would block the user's own edits
        // while protecting nothing the lock does not already cover.
        None => {
            let pins = if relaxed {
                "files pinned by OpenMoat differ only in settings that change no decision"
            } else {
                "every file pinned by OpenMoat matches the policy lock"
            };
            decision
                .reasons
                .push(format!("{source} {change} (no file named); {pins}"));
            return Ok(decision);
        }
    };
    // A settings-review copy holds exactly what its target will become, so the
    // target's pin decides: block unless the copy leaves the pinned file as is.
    // Only a person re-pins, and the hook cannot tell an owner's accept in
    // `/settings-review` from an agent's, so any edit of a pinned file is refused.
    if let Some(target) = path.to_str().and_then(openmoat_hosts::proposal_target)
        && lock.pins(std::path::Path::new(&target))
    {
        if let Some(drift) = lock.verify_proposal(path, std::path::Path::new(&target)) {
            let mut deny = Decision::new(Verdict::Deny);
            deny.rules.push(INTEGRITY_RULE.to_owned());
            deny.reasons.push(format!(
                "{drift}; OpenMoat pinned {target}, so the proposal is not applied. Edit the file yourself and run `moat doctor --accept` to change it"
            ));
            return Ok(deny);
        }
        decision
            .reasons
            .push(format!("{} leaves {target} as pinned", path.display()));
        return Ok(decision);
    }
    let pinned = if lock.verify_one(path).is_some() {
        "differs from the policy lock only in settings that change no decision; `moat doctor --accept` re-pins"
    } else if lock.pins(path) {
        "matches the policy lock"
    } else {
        "not pinned by OpenMoat"
    };
    decision
        .reasons
        .push(format!("{} {change}; {pinned}", path.display()));
    Ok(decision)
}

fn drift_blocks_change(drift: &[Drift]) -> Decision {
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(format!(
            "{d} outside OpenMoat; the change is not loaded into this session. Run `moat doctor` to inspect, `moat doctor --accept` to accept it"
        ));
    }
    decision
}
