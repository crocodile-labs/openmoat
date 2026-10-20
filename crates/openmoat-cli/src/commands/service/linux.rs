//! Linux: a systemd user unit at `~/.config/systemd/user/moat-proxy.service`.
//!
//! `systemctl --user daemon-reload && systemctl --user enable --now moat-proxy`
//! loads it, `systemctl --user is-active` reports its state, and
//! `systemctl --user disable --now moat-proxy && rm <unit>` undoes it. The
//! user bus is a hard requirement: `systemctl --user` without one (bare
//! containers, some CI runners) fails fast with a clear hint, not silently.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use super::{Manager, State, unit};
use crate::home::{Home, user_home, write_private};
use crate::install::{SANDBOX_BACKUP, backup_path};

pub const DISPLAY: &str = "systemd user unit";

/// Build a Linux service manager rooted at this user's home.
pub fn manager(_home: &Home) -> Result<Box<dyn Manager>> {
    Ok(Box::new(SystemdManager { home: user_home()? }))
}

struct SystemdManager {
    home: PathBuf,
}

impl SystemdManager {
    fn unit_dir(&self) -> PathBuf {
        self.home.join(".config/systemd/user")
    }

    fn unit_path(&self) -> PathBuf {
        self.unit_dir().join(unit::NAME)
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
        .with_context(
            || "running systemctl --user; install systemd or run `openmoat proxy` yourself",
        )
}

impl Manager for SystemdManager {
    fn file_path(&self) -> Result<PathBuf> {
        Ok(self.unit_path())
    }

    fn install(&self, binary: &Path, moat_home: &Path) -> Result<PathBuf> {
        let dir = self.unit_dir();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let text = unit::render(&unit::Spec { binary, moat_home });
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
                 `systemctl --user enable --now moat-proxy` runs it by hand",
                String::from_utf8_lossy(&reload.stderr).trim(),
                path.display(),
            );
        }
        let start = systemctl(["enable", "--now", unit::NAME])?;
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
            let _ = systemctl(["disable", "--now", unit::NAME]);
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
        let active = match systemctl(["is-active", unit::NAME]) {
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
            "failed" => classify_failure(),
            "inactive" | "deactivating" => classify_inactive(),
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
        let out = systemctl(["restart", unit::NAME])?;
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
fn classify_failure() -> Result<State> {
    let out = systemctl(["show", unit::NAME, "-p", "ExecMainStatus", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim() == "64" {
        return Ok(State::DriftBlocked);
    }
    Ok(State::Crashlooping)
}

/// An `inactive` unit: usually just stopped, but a one-shot exit 64 that
/// systemd read as success (type=simple, treats clean exit as inactive) also
/// counts as drift.
fn classify_inactive() -> Result<State> {
    let out = systemctl(["show", unit::NAME, "-p", "ExecMainStatus", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim() == "64" {
        return Ok(State::DriftBlocked);
    }
    Ok(State::Stopped)
}
