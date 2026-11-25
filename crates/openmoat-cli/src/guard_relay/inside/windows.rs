//! Windows: the guard under `openmoat run` could not write the audit log, so
//! the lock is opened for writing instead (nothing is written): the state
//! directory's access list names the person's account and `SYSTEM` only
//! (ADR-083), so under the run that open fails with `ERROR_ACCESS_DENIED`.
//!
//! What tells the run apart from a lock that is only read-only is this
//! process's token, which no variable and no hook setting can change:
//! - under the write-restricted token (ADR-115) the token is restricted;
//! - as the agent account (ADR-129) its user is a SID that setup registered
//!   under `HKLM\SOFTWARE\OpenMoat`, where only an administrator can write.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: i32 = 5;

/// Whether this process's token is a Windows run's.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    restricted: bool,
    agent_account: bool,
}

impl Probe {
    /// This process.
    pub fn system() -> Self {
        let restricted = crate::commands::run_in_restricted_token();
        Self {
            restricted,
            agent_account: !restricted && crate::commands::run_as_agent_account(),
        }
    }
}

/// Open the lock as the run's agent would have to for the audit log: for
/// writing, without changing it.
pub(super) fn open_lock(lock: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(lock)
}

pub(super) fn refused_by_sandbox(error: &io::Error, probe: Probe) -> bool {
    (probe.restricted || probe.agent_account) && error.raw_os_error() == Some(ACCESS_DENIED)
}

/// A process in no sandbox, for the tests.
#[cfg(test)]
pub(super) fn unconfined() -> Probe {
    Probe {
        restricted: false,
        agent_account: false,
    }
}

/// The refusal a guard under `openmoat run` gets, for the tests.
#[cfg(test)]
pub(super) fn run_sandbox() -> (io::Error, Probe) {
    (
        io::Error::from_raw_os_error(ACCESS_DENIED),
        Probe {
            restricted: true,
            agent_account: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As the agent account, the same refusal is relayed; outside both, never.
    #[test]
    fn the_agent_accounts_refusal_is_relayed() {
        let denied = io::Error::from_raw_os_error(ACCESS_DENIED);
        let account = Probe {
            restricted: false,
            agent_account: true,
        };
        assert!(refused_by_sandbox(&denied, account));
        assert!(!refused_by_sandbox(&denied, unconfined()));
        let missing = io::Error::from(io::ErrorKind::NotFound);
        assert!(!refused_by_sandbox(&missing, account));
    }
}
