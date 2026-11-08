//! Elsewhere `openmoat run` has no sandbox, so no guard is in one.

use std::io;

/// Nothing to read of this process here.
#[derive(Debug, Clone, Copy)]
pub struct Probe;

impl Probe {
    /// This process.
    pub fn system() -> Self {
        Self
    }
}

pub(super) fn refused_by_sandbox(_: &io::Error, _: Probe) -> bool {
    false
}

/// A process in no sandbox, for the tests.
#[cfg(test)]
pub(super) fn unconfined() -> Probe {
    Probe
}
