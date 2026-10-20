//! Claude Code's `ConfigChange` hook: whether a settings file that changed on
//! disk may load into the running session.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::HookRequest;

use crate::home::Home;
use crate::integrity::{self, Drift, INTEGRITY_RULE, Lock};
use crate::project_settings;

const CONFIG_CHANGE_RULE: &str = "config-change";

/// The project settings file a `project_settings` or `local_settings` change
/// is about; `None` for user settings and every other source.
fn project_file(source: &str) -> Option<&'static str> {
    match source {
        "project_settings" => Some(project_settings::FILES[0]),
        "local_settings" => Some(project_settings::FILES[1]),
        _ => None,
    }
}

/// A settings file changed on disk. While a pinned file drifted beyond the
/// settings `integrity/relaxed.rs` lets the guard decide through, no change is
/// loaded: the session keeps the old settings and the drift is reported.
/// Otherwise a pinned file loads (it matches the lock, or differs only in those
/// settings), a settings-review copy of one loads only if it leaves the pinned
/// file as is, and an unpinned project or local settings file loads only if it
/// sets nothing `project_settings::findings` names. Anything else is audited
/// and allowed.
pub(super) fn decision(
    home: &Home,
    request: &HookRequest,
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
    let path = match &request.action {
        Some(openmoat_core::Action::FsWrite { path }) => Path::new(path),
        Some(_) => bail!("config change for something other than a file"),
        // Claude Code may report a change without naming the file. Every pin
        // matches, and refusing the change would block the user's own edits
        // while protecting nothing the lock does not already cover. A project
        // level's file is found from the session's directory and checked.
        None => {
            if let Some(name) = project_file(source) {
                for file in unnamed_project_files(request.cwd.as_deref(), name)? {
                    if !lock.pins(&file)
                        && let Some(blocked) = project_change(&file)
                    {
                        return Ok(blocked);
                    }
                }
            }
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
    let target = path.to_str().and_then(openmoat_hosts::proposal_target);
    if let Some(target) = &target
        && lock.pins(Path::new(target))
    {
        if let Some(drift) = lock.verify_proposal(path, Path::new(target)) {
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
    // An unpinned project or local file (or a review copy of one, which holds
    // what it will become) comes from the repository: checked by its contents.
    if project_file(source).is_some()
        && !lock.pins(path)
        && let Some(blocked) = project_change(path)
    {
        return Ok(blocked);
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

/// The project files named `name` a change that names no file may be about,
/// found from the session's directory (the guard's own when Claude Code sent
/// none).
fn unnamed_project_files(cwd: Option<&str>, name: &str) -> Result<Vec<PathBuf>> {
    let cwd = match cwd {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir().context("resolving working directory")?,
    };
    Ok(project_settings::candidates(
        &cwd,
        &crate::home::user_home()?,
        name,
    ))
}

/// A block for a project settings file that sets something that could turn
/// OpenMoat off, run a program or redirect the agent, or that cannot be read;
/// `None` when it may load.
fn project_change(path: &Path) -> Option<Decision> {
    let found = project_settings::check(path)?;
    let mut deny = Decision::new(Verdict::Deny);
    deny.rules.push(project_settings::RULE.to_owned());
    deny.reasons.push(format!(
        "{} (project settings) {found}; the change is not loaded into this session. Review the file and remove what you did not add; a new session loads the file as it is",
        path.display()
    ));
    Some(deny)
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

#[cfg(test)]
mod tests;
