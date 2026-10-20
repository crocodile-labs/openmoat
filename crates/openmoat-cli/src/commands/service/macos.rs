//! macOS: a per-user launchd agent at `~/Library/LaunchAgents/dev.openmoat.proxy.plist`.
//!
//! `launchctl bootstrap gui/<uid> <plist>` loads it, `launchctl kickstart`
//! starts it, `launchctl print` returns its state, and `launchctl bootout`
//! stops and unloads it. `launchctl` not on PATH is reported, not pretended
//! away: the state becomes `Unknown` and `install` fails with a clear hint.
//!
//! The plist's bytes come from [`super::plist::render`]; this file is only
//! the I/O and `launchctl` glue around it. `unsafe` is forbidden workspace-wide
//! (`AGENTS.md` §4), so the uid for the gui domain is read by running
//! `/usr/bin/id -u`, which is a shipped macOS binary; its absence is reported.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use super::{Manager, State, plist};
use crate::home::{Home, user_home, write_private};
use crate::install::{SANDBOX_BACKUP, backup_path};

pub const DISPLAY: &str = "launchd user agent";

/// Build a macOS service manager rooted at this user's home.
pub fn manager(_home: &Home) -> Result<Box<dyn Manager>> {
    Ok(Box::new(LaunchdManager { home: user_home()? }))
}

struct LaunchdManager {
    home: PathBuf,
}

impl LaunchdManager {
    fn plist_dir(&self) -> PathBuf {
        self.home.join("Library/LaunchAgents")
    }

    fn plist_path(&self) -> PathBuf {
        self.plist_dir().join(format!("{}.plist", plist::LABEL))
    }
}

fn log_dir() -> Result<PathBuf> {
    Ok(Home::locate()?.root().join("logs"))
}

/// The gui domain target launchd uses for a user agent: `gui/<uid>/<label>`.
/// A zero uid would mean "root at the login window", which is not what a
/// user agent runs as; refuse rather than silently load into gui/0.
fn target() -> Result<String> {
    let uid = current_uid()?;
    if uid == 0 {
        bail!("`openmoat proxy install` is for a logged-in user, not root");
    }
    Ok(format!("gui/{uid}/{}", plist::LABEL))
}

fn gui_domain() -> Result<String> {
    Ok(format!("gui/{}", current_uid()?))
}

/// Run `launchctl` with the given arguments. An absent `launchctl` is
/// surfaced rather than treated as "not loaded".
fn launchctl<I, S>(args: I) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("launchctl").args(args).output().with_context(
        || "running launchctl; install launchd command-line tools or run `openmoat proxy` yourself",
    )
}

impl Manager for LaunchdManager {
    fn file_path(&self) -> Result<PathBuf> {
        Ok(self.plist_path())
    }

    fn install(&self, binary: &Path, moat_home: &Path) -> Result<PathBuf> {
        let dir = self.plist_dir();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let logs = log_dir()?;
        fs::create_dir_all(&logs).with_context(|| format!("creating {}", logs.display()))?;
        let stdout_log = logs.join("proxy.out.log");
        let stderr_log = logs.join("proxy.err.log");
        let text = plist::render(&plist::Spec {
            binary,
            moat_home,
            stdout_log: &stdout_log,
            stderr_log: &stderr_log,
        });
        let path = self.plist_path();
        // Back up an existing plist once per `install`, so a hand-edited
        // file is never lost silently.
        if path.exists() {
            let backup = backup_path(&path, SANDBOX_BACKUP);
            fs::copy(&path, &backup).with_context(|| format!("backing up {}", path.display()))?;
        }
        write_private(&path, text.as_bytes())?;
        if super::skip_exec() {
            return Ok(path);
        }
        // Unload-then-load is idempotent: launchd refuses a second bootstrap
        // for the same label. A failing `bootout` is fine when it was not
        // loaded.
        let _ = launchctl(["bootout", &target()?])?;
        let out = launchctl(["bootstrap", &gui_domain()?, &path.to_string_lossy()])?;
        if !out.status.success() {
            bail!(
                "launchctl bootstrap refused: {}; the plist is at {} and `launchctl \
                 bootstrap {} {}` runs it by hand",
                String::from_utf8_lossy(&out.stderr).trim(),
                path.display(),
                gui_domain()?,
                path.display()
            );
        }
        let _ = launchctl(["kickstart", "-k", &target()?])?;
        Ok(path)
    }

    fn uninstall(&self) -> Result<Option<PathBuf>> {
        let path = self.plist_path();
        if !path.exists() {
            return Ok(None);
        }
        if !super::skip_exec() {
            let _ = launchctl(["bootout", &target()?]);
        }
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        Ok(Some(path))
    }

    fn state(&self) -> Result<State> {
        let path = self.plist_path();
        if !path.exists() {
            return Ok(State::NotInstalled);
        }
        if super::skip_exec() {
            // Treat the file-only install as stopped: the test skipped the
            // bootstrap, so launchd knows nothing of this label.
            return Ok(State::Stopped);
        }
        let out = match launchctl(["print", &target()?]) {
            Ok(out) => out,
            Err(e) => {
                return Ok(State::Unknown {
                    details: format!("{e:#}"),
                });
            }
        };
        if !out.status.success() {
            return Ok(State::Stopped);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // `launchctl print` lists `pid = <n>` for a running service and
        // `last exit code = <n>` after one exit. `state = running` is also
        // reliable on recent macOS.
        if stdout.contains("state = running") || stdout.contains("\n\tpid = ") {
            return Ok(State::Running);
        }
        if let Some(code) = parse_last_exit(&stdout) {
            if code == 64 {
                return Ok(State::DriftBlocked);
            }
            if code != 0 {
                return Ok(State::Crashlooping);
            }
        }
        Ok(State::Stopped)
    }

    fn restart(&self) -> Result<()> {
        let path = self.plist_path();
        if !path.exists() || super::skip_exec() {
            return Ok(());
        }
        let out = launchctl(["kickstart", "-k", &target()?])?;
        if !out.status.success() {
            bail!(
                "launchctl kickstart refused: {}; the proxy may already be stopped",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

/// Current effective uid, read by running `/usr/bin/id -u`. Workspace lints
/// forbid `unsafe` (so no direct `getuid` call); `id` is shipped on every macOS.
fn current_uid() -> Result<u32> {
    let out = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .context("running /usr/bin/id to find the current uid")?;
    if !out.status.success() {
        bail!(
            "/usr/bin/id -u failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .parse::<u32>()
        .with_context(|| format!("parsing uid {text:?}"))
}

/// Read the exit code from one `last exit code = N` line, when present.
fn parse_last_exit(text: &str) -> Option<i32> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("last exit code = "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_last_exit_reads_the_exit_code_line() {
        let text = "foo = bar\n\tlast exit code = 64\nmore";
        assert_eq!(parse_last_exit(text), Some(64));
        assert_eq!(parse_last_exit("no exit code here"), None);
        let crash = "\tlast exit code = 139 (signal 11)\n";
        assert_eq!(parse_last_exit(crash), Some(139));
    }
}
