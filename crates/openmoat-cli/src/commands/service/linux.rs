//! Linux: a systemd user unit at `~/.config/systemd/user/<unit>`
//! (`moat-proxy.service`, `openmoat-approvals.service`).
//!
//! `systemctl --user daemon-reload && systemctl --user enable --now <unit>`
//! loads it, `systemctl --user is-active` reports its state, and
//! `systemctl --user disable --now <unit> && rm <unit>` undoes it. The
//! user bus is a hard requirement: `systemctl --user` without one (bare
//! containers, some CI runners) fails fast with a clear hint, not silently.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use super::{Job, Manager, State, unit};
use crate::home::{Home, user_home, write_private};
use crate::install::{SANDBOX_BACKUP, backup_path};

pub const DISPLAY: &str = "systemd user unit";

/// What systemd sets in the environment of each service it starts.
const INVOCATION_ID: &str = "INVOCATION_ID";

/// Build a Linux service manager for `job`, rooted at this user's home.
pub fn manager(_home: &Home, job: &'static Job) -> Result<Box<dyn Manager>> {
    Ok(Box::new(SystemdManager {
        home: user_home()?,
        job,
    }))
}

struct SystemdManager {
    home: PathBuf,
    job: &'static Job,
}

impl SystemdManager {
    fn unit_dir(&self) -> PathBuf {
        self.home.join(".config/systemd/user")
    }

    fn unit_path(&self) -> PathBuf {
        self.unit_dir().join(self.job.unit)
    }
}

fn systemctl<I, S>(args: I) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .context("running systemctl --user; install systemd")
}

/// Where `systemctl` is, by absolute path: never one found on a `PATH` the
/// service's environment may have changed.
const SYSTEMCTL: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// What systemd loaded for `unit` ([`super::loaded::systemd`]), asked of the
/// user manager with only the variables that find its bus.
fn shown(unit: &str) -> Result<String> {
    let program = SYSTEMCTL
        .iter()
        .find(|p| Path::new(p).is_file())
        .context("systemctl is not in /usr/bin or /bin")?;
    let mut command = Command::new(program);
    command.env_clear().env("LC_ALL", "C");
    for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let out = command
        .args([
            "--user",
            "show",
            unit,
            "-p",
            "FragmentPath",
            "-p",
            "DropInPaths",
        ])
        .args(["-p", "NeedDaemonReload", "-p", "ExecStart"])
        .output()
        .context("asking systemd what it loaded")?;
    if !out.status.success() {
        bail!(
            "systemctl --user show {unit} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Manager for SystemdManager {
    fn file_path(&self) -> Result<PathBuf> {
        Ok(self.unit_path())
    }

    fn render(&self, binary: &Path, moat_home: &Path) -> Result<String> {
        let (stdout, stderr) = super::log_paths(self.job)?;
        Ok(unit::render(&unit::Spec {
            job: self.job,
            binary,
            moat_home,
            logs: (&stdout, &stderr),
        }))
    }

    fn environment(&self) -> fn(&str) -> Option<Vec<String>> {
        unit::environment
    }

    fn job(&self) -> &'static Job {
        self.job
    }

    /// systemd starts a service with `INVOCATION_ID` set, in a control group
    /// named after its unit (`…/app.slice/<unit>`).
    fn started_as_service(&self, program: &[String]) -> Result<()> {
        let group = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let in_unit = group
            .lines()
            .any(|line| line.trim_end().rsplit('/').next() == Some(self.job.unit));
        if std::env::var_os(INVOCATION_ID).is_none() || !in_unit {
            bail!("systemd did not start this as `{}`", self.job.unit);
        }
        let show = shown(self.job.unit)?;
        let findings = super::loaded::systemd(&show, &self.unit_path(), program);
        if !findings.is_empty() {
            bail!(
                "refusing to run as `{}`: {}; `{}` writes it again",
                self.job.unit,
                findings.join("; "),
                self.job.install
            );
        }
        Ok(())
    }

    fn install(&self, binary: &Path, moat_home: &Path) -> Result<PathBuf> {
        let dir = self.unit_dir();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        super::prepare_logs(self.job)?;
        let text = self.render(binary, moat_home)?;
        let path = self.unit_path();
        if path.exists() {
            let backup = backup_path(&path, SANDBOX_BACKUP);
            fs::copy(&path, &backup).with_context(|| format!("backing up {}", path.display()))?;
        }
        write_private(&path, text.as_bytes())?;
        if super::skip_exec() {
            return Ok(path);
        }
        // `daemon-reload` picks up the new file; `enable --now` starts it and
        // links it under `default.target.wants/` so it comes back on next
        // login. A missing user bus (headless container) surfaces here.
        let reload = systemctl(["daemon-reload"])?;
        if !reload.status.success() {
            bail!(
                "systemctl --user daemon-reload refused: {}; the unit is at {} and \
                 `systemctl --user enable --now {}` runs it by hand",
                String::from_utf8_lossy(&reload.stderr).trim(),
                path.display(),
                self.job.unit,
            );
        }
        let start = systemctl(["enable", "--now", self.job.unit])?;
        if !start.status.success() {
            bail!(
                "systemctl --user enable --now refused: {}; the unit is at {}",
                String::from_utf8_lossy(&start.stderr).trim(),
                path.display(),
            );
        }
        Ok(path)
    }

    fn uninstall(&self) -> Result<Option<PathBuf>> {
        let path = self.unit_path();
        if !path.exists() {
            return Ok(None);
        }
        if !super::skip_exec() {
            // Best effort: a user bus that is gone leaves `--user disable` to fail,
            // and that is fine — we still remove the unit file.
            let _ = systemctl(["disable", "--now", self.job.unit]);
        }
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        if !super::skip_exec() {
            let _ = systemctl(["daemon-reload"]);
        }
        Ok(Some(path))
    }

    fn state(&self) -> Result<State> {
        let path = self.unit_path();
        if !path.exists() {
            return Ok(State::NotInstalled);
        }
        if super::skip_exec() {
            // Treat the file-only install as stopped: the test skipped the
            // bootstrap, so systemd knows nothing of this unit.
            return Ok(State::Stopped);
        }
        let active = match systemctl(["is-active", self.job.unit]) {
            Ok(out) => out,
            Err(e) => {
                return Ok(State::Unknown {
                    details: format!("{e:#}"),
                });
            }
        };
        let text = String::from_utf8_lossy(&active.stdout);
        match text.trim() {
            "active" | "activating" | "reloading" => Ok(State::Running),
            "failed" => classify_failure(self.job),
            "inactive" | "deactivating" => classify_inactive(self.job),
            other => Ok(State::Unknown {
                details: format!("systemctl is-active returned {other:?}"),
            }),
        }
    }

    fn restart(&self) -> Result<()> {
        let path = self.unit_path();
        if !path.exists() || super::skip_exec() {
            return Ok(());
        }
        let out = systemctl(["restart", self.job.unit])?;
        if !out.status.success() {
            bail!(
                "systemctl --user restart refused: {}",
                String::from_utf8_lossy(&out.stderr).trim(),
            );
        }
        Ok(())
    }
}

/// A `failed` unit: a lock-drift exit (code 64) means the user must look at
/// `moat doctor`, not a crash loop. Everything else is treated as a crash loop.
fn classify_failure(job: &Job) -> Result<State> {
    let out = systemctl(["show", job.unit, "-p", "ExecMainStatus", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim() == "64" {
        return Ok(State::DriftBlocked);
    }
    Ok(State::Crashlooping)
}

/// An `inactive` unit: usually just stopped, but a one-shot exit 64 that
/// systemd read as success (type=simple, treats clean exit as inactive) also
/// counts as drift.
fn classify_inactive(job: &Job) -> Result<State> {
    let out = systemctl(["show", job.unit, "-p", "ExecMainStatus", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim() == "64" {
        return Ok(State::DriftBlocked);
    }
    Ok(State::Stopped)
}
