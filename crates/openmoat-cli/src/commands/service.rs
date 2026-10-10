//! User-level service installation for `moat proxy` (ADR-020, #272).
//!
//! `moat proxy install` writes a launchd user agent (macOS) or a systemd user
//! unit (Linux) that keeps `moat proxy` running under the current user, with
//! `MOAT_HOME` set to the directory `moat` found this run; `moat proxy
//! uninstall` removes it; `moat proxy status` and `moat doctor` report its
//! state. Windows is refused for now (#272 defers Standard-tier proxy routing).
//!
//! A lock-drift exit from the proxy is deliberately an exit, not a
//! loop-restart: launchd's `KeepAlive = {SuccessfulExit=false}` and systemd's
//! `Restart=on-failure` leave a clean exit alone, so `moat doctor` can surface
//! the drift to a person instead of hammering the audit log with crash events.
//!
//! The service file goes next to the host's own unit directory with owner-only
//! permissions (`0o600` on Linux; launchd keeps `~/Library/LaunchAgents`
//! private to the user); `MOAT_HOME` is a path, never a secret, and token
//! environment variables are read from the broker at run time, never written
//! into the plist or unit.

// The plist and unit emitters are pure string functions. Each one is used
// only by its own platform (`macos.rs`, `linux.rs`), so a cross-platform
// build sees the other as unused; the `cfg` gating keeps the warnings away
// without turning off `-D warnings`.
#[cfg(any(target_os = "macos", test))]
pub mod plist;
#[cfg(any(target_os = "linux", test))]
pub mod unit;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as platform;

use std::path::PathBuf;

use anyhow::Result;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use serde::Serialize;

use crate::home::Home;

/// Debug builds honour `MOAT_SERVICE_SKIP_EXEC=1`: the service file is still
/// written and removed, but `launchctl` / `systemctl` are never invoked. End-to-end
/// tests can exercise the install path without touching the host's real service
/// manager (and never see a plist loaded into the developer's own launchd).
/// Release builds (`cargo install`, distributed binaries) do not contain this
/// check at all. Only compiled where a service manager invokes it (macOS, Linux);
/// the Windows stub has nothing to skip.
#[cfg(all(any(target_os = "macos", target_os = "linux"), debug_assertions))]
pub(crate) fn skip_exec() -> bool {
    std::env::var_os("MOAT_SERVICE_SKIP_EXEC").is_some_and(|v| v == "1")
}

#[cfg(all(any(target_os = "macos", target_os = "linux"), not(debug_assertions)))]
pub(crate) fn skip_exec() -> bool {
    false
}

/// What a service manager reports about `moat proxy`. Only macOS and Linux
/// have a service manager to ask, so the type exists only there; the Windows
/// stub has no state to report (#272).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum State {
    /// No service file on disk.
    NotInstalled,
    /// Service file is on disk but not loaded.
    Stopped,
    /// Loaded and the process is up.
    Running,
    /// The service exited cleanly (exit 64); treat as drift the user must look
    /// at, not as a crash to restart (`moat doctor` names the reason).
    DriftBlocked,
    /// The service restarted more than its burst limit allows; a user who
    /// edits the plist/unit by hand or whose binary is missing lands here.
    Crashlooping,
    /// The host's own service tooling is missing or refused to answer
    /// (`launchctl` not found, `systemctl --user` without a user bus); the
    /// reason is in `details`.
    Unknown { details: String },
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl State {
    /// A short line for `moat status` / `moat doctor`.
    pub fn describe(&self, path: &std::path::Path) -> String {
        match self {
            Self::NotInstalled => {
                "not installed; `moat proxy install` keeps the proxy running".to_owned()
            }
            Self::Stopped => format!("installed but stopped ({})", path.display()),
            Self::Running => format!("installed and running ({})", path.display()),
            Self::DriftBlocked => format!(
                "installed; the proxy exited because of policy-lock drift. Fix the drift \
                 (`moat doctor`), then `moat proxy install` restarts it ({})",
                path.display()
            ),
            Self::Crashlooping => format!(
                "installed; restart budget exhausted. Check the service log, then \
                 `moat proxy install` to retry ({})",
                path.display()
            ),
            Self::Unknown { details } => format!("installed; state unknown: {details}"),
        }
    }
}

/// What the service wrapper does. The real implementations are
/// platform-selected ([`platform::manager`]); in-process tests set
/// `MOAT_SERVICE_SKIP_EXEC=1` to write the file without touching
/// `launchctl`/`systemctl`. Reading the state and restarting exist only where
/// a service can be installed (macOS, Linux).
pub trait Manager {
    /// Write the file (owner-only), load it and start it. Returns the path
    /// written to.
    fn install(&self, binary: &std::path::Path, moat_home: &std::path::Path) -> Result<PathBuf>;
    /// Stop and remove the file. Returns the path removed, or `None` when
    /// nothing was installed.
    fn uninstall(&self) -> Result<Option<PathBuf>>;
    /// Where the service file lives on disk.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn file_path(&self) -> Result<PathBuf>;
    /// What state the service is in now.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn state(&self) -> Result<State>;
    /// Reload: pick up a changed policy (`moat sandbox sync`), by restarting.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn restart(&self) -> Result<()>;
}

/// The platform's service manager, or an error wrapper on an unsupported OS
/// (Windows is a stub). The log paths live under `MOAT_HOME/logs/` so a user
/// can read them without `sudo` on macOS.
pub fn manager(home: &Home) -> Result<Box<dyn Manager>> {
    platform::manager(home)
}

/// Human-readable name for the launchd agent / systemd user unit, so the
/// commands all speak of the same thing.
pub fn display_name() -> &'static str {
    platform::DISPLAY
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn state_describe_names_the_fix_for_each_variant() {
        let path = std::path::Path::new("/x/plist");
        assert!(State::NotInstalled.describe(path).contains("not installed"));
        assert!(State::Stopped.describe(path).contains("stopped"));
        assert!(State::Running.describe(path).contains("running"));
        assert!(State::DriftBlocked.describe(path).contains("drift"));
        assert!(State::Crashlooping.describe(path).contains("restart"));
        assert!(
            State::Unknown {
                details: "no bus".into(),
            }
            .describe(path)
            .contains("no bus")
        );
    }
}
