//! The audit log's directory on Linux, where Claude Code's sandbox hides only
//! the files a `denyRead` glob matches when each command starts.
//!
//! `SQLite` keeps a `-wal` and a `-shm` file beside the audit log while a
//! connection has it open and removes them when the last one closes, so they
//! come and go as `openmoat guard` runs. `audit.db*` names them by a glob,
//! which the runtime expands when a command starts, and a path missing then
//! it skips: one created while the command runs stays readable to it. So on
//! Linux the directory holding the audit log is hidden whole.

use openmoat_core::Kind;

use super::{Filesystem, Report};
use crate::sandbox::patterns::{has_glob, push_unique};

/// The audit log's glob in a `kernel-self` read deny: the database and the
/// files beside it (`-wal`, `-shm`, `-journal`).
const AUDIT_LOG: &str = "/audit.db*";

impl Filesystem {
    /// Add to `denyRead` each literal directory a `denyRead` entry names the
    /// audit log in (`/home/me/.moat/audit.db*` → `/home/me/.moat`). Under the
    /// home directory Claude Code hides it already; moved elsewhere
    /// (`MOAT_HOME`), its policy is hidden from sandboxed commands too.
    pub(super) fn hide_state_dirs(&mut self, report: &mut Report) {
        let dirs: Vec<String> = self
            .deny_read
            .iter()
            .filter_map(|entry| entry.strip_suffix(AUDIT_LOG))
            .filter(|dir| dir.starts_with('/') && !has_glob(dir))
            .map(str::to_owned)
            .collect();
        if dirs.is_empty() {
            return;
        }
        for dir in &dirs {
            push_unique(&mut self.deny_read, dir.clone());
        }
        report.loss(
            Kind::FsRead,
            "claude-code.linux-state-dir",
            format!(
                "on Linux Claude Code hides only the files a denyRead glob matches when each \
                 command starts, and the audit log's `-wal` and `-shm` files come and go, so \
                 OpenMoat's state directory is hidden whole from sandboxed commands, its \
                 policy included: {}",
                dirs.join(", ")
            ),
        );
    }
}
