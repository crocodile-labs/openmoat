//! User-level services: `openmoat proxy` (ADR-020, #272) and `openmoat
//! approvals listen` (ADR-094), each described by a [`Job`].
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
mod job;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod lines;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub mod loaded;
#[cfg(any(target_os = "macos", test))]
pub mod plist;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub mod read_back;
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

pub use job::{APPROVALS, Job, PROXY};

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
    /// A short line for `moat status` / `moat doctor` about `job`.
    pub fn describe(&self, job: &Job, path: &std::path::Path) -> String {
        match self {
            Self::NotInstalled => {
                format!(
                    "not installed; `{}` keeps {} running",
                    job.install, job.noun
                )
            }
            Self::Stopped => format!("installed but stopped ({})", path.display()),
            Self::Running => format!("installed and running ({})", path.display()),
            Self::DriftBlocked => format!("installed; {} ({})", job.exit_64, path.display()),
            Self::Crashlooping => format!(
                "installed; restart budget exhausted. Check the service log, then \
                 `{}` to retry ({})",
                job.install,
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
    /// The file [`Self::install`] writes for `binary` and `moat_home`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn render(&self, binary: &std::path::Path, moat_home: &std::path::Path) -> Result<String>;
    /// The variables a service file of this platform's format sets
    /// ([`read_back::findings`]).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn environment(&self) -> fn(&str) -> Option<Vec<String>>;
    /// The job this manager installs.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn job(&self) -> &'static Job;
    /// Refused unless this process was started by the service manager as the
    /// job's service, from the installed file alone, running `program` (the
    /// installed binary and the job's arguments, [`loaded`]). A consistency
    /// check, not a boundary: a process of the same user can imitate what it
    /// reads (ADR-094).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn started_as_service(&self, program: &[String]) -> Result<()>;
    /// What state the service is in now.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn state(&self) -> Result<State>;
    /// Reload: pick up a changed policy (`moat sandbox sync`), by restarting.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn restart(&self) -> Result<()>;
}

/// The platform's service manager for `job`, or an error wrapper on an
/// unsupported OS (Windows is a stub). The log paths live under
/// `MOAT_HOME/logs/` so a user can read them without `sudo` on macOS.
pub fn manager(home: &Home, job: &'static Job) -> Result<Box<dyn Manager>> {
    platform::manager(home, job)
}

/// Why the installed service file is not the one `moat proxy install` writes
/// for `binary` and `moat_home` ([`read_back`](mod@read_back)); empty when it is, or when
/// nothing is installed. A file that cannot be read is a finding too.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn read_back(
    manager: &dyn Manager,
    binary: &std::path::Path,
    moat_home: &std::path::Path,
) -> Vec<String> {
    let Ok(path) = manager.file_path() else {
        return Vec::new();
    };
    let text = match std::fs::read(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => return vec![format!("cannot be read: {e}")],
    };
    let expected = match manager.render(binary, moat_home) {
        Ok(expected) => expected,
        Err(e) => return vec![format!("cannot be compared: {e:#}")],
    };
    let installed = read_back::Installed {
        text: &text,
        mode: mode(&path),
    };
    read_back::findings(&expected, &installed, manager.environment(), manager.job())
}

/// Refused unless this process runs as `job`'s installed service: the file
/// is there and reads back as exactly what its install command writes for
/// the pinned binary and this state directory (owner-only, `MOAT_HOME` its
/// only variable), and the service manager started this process from it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn check_started(home: &Home, job: &'static Job) -> Result<()> {
    use anyhow::bail;

    let manager = manager(home, job)?;
    let path = manager.file_path()?;
    if !path.exists() {
        bail!(
            "no service is installed at {}; `{}` installs it, and a person runs \
             `openmoat {}` in a terminal",
            path.display(),
            job.install,
            job.terminal
        );
    }
    let findings = lines::findings(home, manager.as_ref());
    if !findings.is_empty() {
        bail!(
            "refusing to run from the service file {}: it {}; `{}` writes it again",
            path.display(),
            findings.join("; it "),
            job.install
        );
    }
    let binary = crate::install::hook_binary()?;
    let program: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
        .chain(job.args.iter().map(|a| (*a).to_owned()))
        .collect();
    manager.started_as_service(&program)
}

/// No user service here, so nothing runs as one.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn check_started(_home: &Home, job: &'static Job) -> Result<()> {
    anyhow::bail!(
        "no user service on {}; run `openmoat {}` in a terminal",
        std::env::consts::OS,
        job.terminal
    )
}

/// `job`'s log files, `MOAT_HOME/logs/<log>.out.log` and `<log>.err.log`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn log_paths(job: &Job) -> Result<(PathBuf, PathBuf)> {
    let logs = Home::locate()?.root().join("logs");
    Ok((
        logs.join(format!("{}.out.log", job.log)),
        logs.join(format!("{}.err.log", job.log)),
    ))
}

/// The log directory, and for a [`Job::private`] job its two log files made
/// owner-only before the service manager opens them: launchd creates a
/// missing one with its own umask (readable by others), and a log the
/// listener writes names approvers and requests.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn prepare_logs(job: &Job) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use anyhow::Context as _;

    let (stdout, stderr) = log_paths(job)?;
    let Some(dir) = stdout.parent() else {
        return Ok(());
    };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    if !job.private {
        return Ok(());
    }
    for path in [&stdout, &stderr] {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("making {} owner-only", path.display()))?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn mode(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
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
        let describe = |state: State| state.describe(&PROXY, path);
        assert!(describe(State::NotInstalled).contains("not installed"));
        assert!(describe(State::Stopped).contains("stopped"));
        assert!(describe(State::Running).contains("running"));
        assert!(describe(State::DriftBlocked).contains("drift"));
        assert!(describe(State::Crashlooping).contains("restart"));
        assert!(
            describe(State::Unknown {
                details: "no bus".into(),
            })
            .contains("no bus")
        );
        // Each job names its own command and what it keeps running.
        let listener = State::NotInstalled.describe(&APPROVALS, path);
        assert!(listener.contains("`openmoat approvals install` keeps the listener"));
        let stopped = State::DriftBlocked.describe(&APPROVALS, path);
        assert!(stopped.contains("its log says why") && !stopped.contains("drift"));
    }
}
