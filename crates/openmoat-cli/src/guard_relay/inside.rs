//! Whether a guard that finds the relay variables really runs inside
//! `openmoat run`'s sandbox.
//!
//! `MOAT_GUARD_SOCKET` and `MOAT_GUARD_TOKEN` are only variables: a host that
//! builds its hooks' environment from a file or setting OpenMoat does not
//! guard would hand them to a hook outside any run, and a listener that
//! repeats the nonce would then answer every call. So the guard relays only
//! when it cannot open its own lock, and only for the reason the run's sandbox
//! gives ([`refused_by_sandbox`]); anywhere else it decides by itself and
//! records that the variables were there ([`RULE_OUTSIDE`]).

use std::io;
use std::path::Path;

// `platform` reads this process: `Probe::system()`, and
// `refused_by_sandbox(error, probe)`, whether the error opening the lock is the
// one `openmoat run`'s sandbox on this OS gives.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod other;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use other as platform;

pub use platform::Probe;

/// The rule of the row a guard leaves when it found the relay variables but
/// was not in a run's sandbox, and so decided the call itself.
pub const RULE_OUTSIDE: &str = "run-guard-outside";

/// Whether the guard should relay: `lock` (the state directory's lock, `None`
/// when no state directory can be named) cannot be opened, and the way it
/// fails is the run's sandbox's.
pub fn in_run_sandbox(lock: Option<&Path>) -> bool {
    let error = match lock.map(std::fs::File::open) {
        Some(Ok(_)) => return false,
        Some(Err(error)) => error,
        None => io::Error::from(io::ErrorKind::NotFound),
    };
    refused_by_sandbox(&error, Probe::system())
}

/// Whether `error`, opening the lock, comes from the sandbox `openmoat run`
/// confines its agent in, as `probe` read this process. A lock that is only
/// missing, or only unreadable by its file mode, is not: a hook outside any
/// run that is given such a state directory decides where it is, and denies.
pub fn refused_by_sandbox(error: &io::Error, probe: Probe) -> bool {
    platform::refused_by_sandbox(error, probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_readable_lock_is_never_relayed() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("policy.lock");
        std::fs::write(&lock, "{}").unwrap();
        assert!(!in_run_sandbox(Some(&lock)));
    }

    #[test]
    fn a_missing_or_mode_locked_lock_outside_a_sandbox_is_not_relayed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = std::fs::File::open(dir.path().join("none/policy.lock")).unwrap_err();
        let outside = platform::unconfined();
        assert!(!refused_by_sandbox(&missing, outside));
        // EACCES, as a state directory of mode 000 gives.
        let by_mode = io::Error::from_raw_os_error(13);
        assert!(!refused_by_sandbox(&by_mode, outside));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn the_run_sandbox_refusal_is_relayed() {
        let (error, probe) = platform::run_sandbox();
        assert!(refused_by_sandbox(&error, probe));
    }
}
