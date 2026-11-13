//! Windows: the state directory's owner and access list (ADR-083), read back
//! in SDDL. The files inside inherit the list unless one was given a list of
//! its own, which is not read here.

use std::path::Path;

use super::Found;
use crate::commands::doctor::Area;
use crate::commands::doctor::rows::Report;
use crate::home::Home;
use crate::state_acl::{self, Judged};

/// The note `doctor` shows instead of a row per file.
pub(super) const NOT_CHECKED: &str = "state files      inherit the state directory's access list; \
                                      a file's own list is not read";

/// What the access list cannot do, said beside every reading of it.
const SAME_ACCOUNT: &str = "state directory  the agent runs as you, so no access list keeps it \
                            out; the hook's `kernel-self` rule and a sandbox do (ADR-083)";

/// No Unix user to compare owners with: the files are not listed one by one.
pub(super) fn current_user() -> Option<u32> {
    None
}

/// Never called: [`current_user`] answers `None`.
pub(super) fn inspect(_: &Path, _: u32) -> Option<Found> {
    None
}

/// One row for the state directory's owner and access list, and the note on
/// what the list cannot do.
pub(super) fn directory(report: &mut Report, home: &Home) {
    let dir = home.root();
    if !dir.is_dir() {
        return;
    }
    match state_acl::read(dir) {
        Ok((me, sddl)) => judged(report, dir, &me, &sddl),
        Err(e) => report.warn(&format!("state directory  access list not read: {e:#}")),
    }
    report.note(SAME_ACCOUNT);
}

fn judged(report: &mut Report, dir: &Path, me: &str, sddl: &str) {
    let judged: Judged = state_acl::judge(sddl, me);
    let shown = dir.display();
    if let Some(owner) = &judged.foreign_owner {
        report.line(
            Area::State,
            false,
            format!(
                "state directory  {shown} is owned by {owner}, not by you, which may change its \
                 access list at any time; fix: move it away and run `openmoat init`, or set \
                 MOAT_HOME to a folder of your own"
            ),
        );
        return;
    }
    let fix = match state_acl::plan(sddl, me) {
        Ok(plan) => format!(
            "fix: `openmoat init` sets it, or by hand: {}",
            state_acl::fix_commands(&state_acl::icacls(), dir, me, &plan).join("; then ")
        ),
        Err(alias) => {
            format!("fix: remove the entry for `{alias}` from it, then run `openmoat init`")
        }
    };
    if !judged.writers.is_empty() {
        report.line(
            Area::State,
            false,
            format!(
                "state directory  {shown} may be changed by {}; {fix}",
                judged.writers.join(", ")
            ),
        );
    } else if !judged.readers.is_empty() {
        report.warn(&format!(
            "state directory  {shown} may be read by {}; {fix}",
            judged.readers.join(", ")
        ));
    } else if !judged.protected {
        report.warn(&format!(
            "state directory  {shown} inherits the access list of the folder above, which may \
             widen it later; {fix}"
        ));
    } else {
        report.line(
            Area::State,
            true,
            format!("state directory  {shown}: no other account may open it"),
        );
    }
}
