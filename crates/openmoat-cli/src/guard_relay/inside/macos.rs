//! macOS: Seatbelt refuses a read its profile denies with `EPERM`. A file
//! mode refuses with `EACCES`, and a missing file is `ENOENT`, so neither is
//! taken for the run's sandbox.

use std::io;

/// `EPERM` on macOS.
const EPERM: i32 = 1;

/// Nothing to read of this process on macOS: the error says it.
#[derive(Debug, Clone, Copy)]
pub struct Probe;

impl Probe {
    /// This process.
    pub fn system() -> Self {
        Self
    }
}

/// Read the lock: Seatbelt refuses reads of the state directory.
pub(super) fn open_lock(lock: &std::path::Path) -> io::Result<std::fs::File> {
    std::fs::File::open(lock)
}

pub(super) fn refused_by_sandbox(error: &io::Error, _: Probe) -> bool {
    error.raw_os_error() == Some(EPERM)
}

/// A process in no sandbox, for the tests.
#[cfg(test)]
pub(super) fn unconfined() -> Probe {
    Probe
}

/// The refusal a guard under `openmoat run` gets, for the tests.
#[cfg(test)]
pub(super) fn run_sandbox() -> (io::Error, Probe) {
    (io::Error::from_raw_os_error(EPERM), Probe)
}
