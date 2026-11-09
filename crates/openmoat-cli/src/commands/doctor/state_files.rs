//! `openmoat doctor`'s rows for the mode and owner of each file in the state
//! directory that decides or records a call (ADR-071): the lock, the policy,
//! the approvals, the trust and host records, the audit log, the keys.
//!
//! The lock pins what these files hold, not who may change them. A file other
//! users may write, or one another user owns, can be replaced under the lock
//! by someone who is not the person: that is a problem row, with the `chmod`
//! or `chown` that fixes it. A file others may read gives away the policy and
//! the log: a warning. Every file's mode and owner is listed with
//! `--verbose`. Where files have no Unix modes (Windows), one note says the
//! check does not run there.

use std::path::{Path, PathBuf};

use super::Area;
use super::human::Place;
use super::rows::Report;
use crate::home::Home;

#[cfg(not(unix))]
mod other;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
use other as platform;
#[cfg(unix)]
use unix as platform;

/// What [`platform::inspect`] found of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Found {
    /// `mode 600, owner you`, as the verbose row shows it.
    pub shown: String,
    /// Another user may change it, or owns it: the problem and its fix.
    pub problem: Option<String>,
    /// Another user may read it: the warning and its fix.
    pub readable: Option<String>,
}

/// The state directory and the files in it that matter, by what they are.
/// The keys' own refusal rows come from `key_file`; here they get only their
/// mode and owner, and a problem when others may write or own them.
fn files(home: &Home) -> Vec<(&'static str, PathBuf, bool)> {
    vec![
        ("state directory", home.root().to_path_buf(), false),
        ("lock", home.lock_path(), false),
        ("policy", home.policy_path(), false),
        ("policy base", home.policy_base_path(), false),
        ("approvals", home.grants_path(), false),
        ("allow rules", home.overlay_path(), false),
        ("trust", home.trust_path(), false),
        ("hosts", home.hosts_path(), false),
        ("environment", home.environment_path(), false),
        ("signers", home.signers_path(), false),
        ("packs", home.packs_path(), false),
        ("audit log", home.audit_path(), false),
        ("proxy key", crate::proxy_session::key_path(home), true),
        ("proxy CA key", crate::proxy_ca::key_path(home), true),
    ]
}

/// The rows for `home`'s state files that exist.
pub(super) fn rows(report: &mut Report, home: &Home) {
    let Some(me) = platform::current_user() else {
        report.note_at(platform::NOT_CHECKED, Place::OpenMoat);
        return;
    };
    for (what, path, key) in files(home) {
        let Some(found) = platform::inspect(&path, me) else {
            continue;
        };
        let label = format!("{what:<17}");
        report.note_at(
            &format!("{label}{} {}", path.display(), found.shown),
            Place::Details,
        );
        if let Some(problem) = &found.problem {
            report.line(Area::State, false, row(&label, &path, problem));
        } else if let Some(readable) = found.readable.as_ref().filter(|_| !key) {
            report.warn(&row(&label, &path, readable));
        }
    }
}

fn row(label: &str, path: &Path, text: &str) -> String {
    format!("{label}{} {text}", path.display())
}

#[cfg(test)]
mod tests;
