//! Windows (ADR-115): a write-restricted token does not restrict reads, so a
//! guard under `openmoat run` can read the state directory's lock, and could
//! not write the audit log. The lock is opened for writing instead (nothing
//! is written): the state directory's access list names the person's account
//! and `SYSTEM` only (ADR-083), so under the run's token that open fails with
//! `ERROR_ACCESS_DENIED`. What tells the run apart from a lock that is only
//! read-only is the token itself: this process's token is restricted, which
//! no variable and no hook setting can make it.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: i32 = 5;

/// Whether this process's token is restricted.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    restricted: bool,
}

impl Probe {
    /// This process.
    pub fn system() -> Self {
        Self {
            restricted: crate::commands::run_in_restricted_token(),
        }
    }
}

/// Open the lock as the run's token would have to for the audit log: for
/// writing, without changing it.
pub(super) fn open_lock(lock: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(lock)
}

pub(super) fn refused_by_sandbox(error: &io::Error, probe: Probe) -> bool {
    probe.restricted && error.raw_os_error() == Some(ACCESS_DENIED)
}

/// A process in no sandbox, for the tests.
#[cfg(test)]
pub(super) fn unconfined() -> Probe {
    Probe { restricted: false }
}

/// The refusal a guard under `openmoat run` gets, for the tests.
#[cfg(test)]
pub(super) fn run_sandbox() -> (io::Error, Probe) {
    (
        io::Error::from_raw_os_error(ACCESS_DENIED),
        Probe { restricted: true },
    )
}
