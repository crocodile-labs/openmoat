//! Whether the running executable is the `openmoat` the policy lock records.
//!
//! A person-only command is refused by name in the guard and by its ancestry
//! here; a copy of the binary under another name, started where the agent is
//! no longer among its ancestors, would get past both. So a person-only command
//! also refuses to run from an executable other than the recorded one, or its
//! `moat` alias, and when it was started under another name (a link named
//! `x` to the recorded binary, or `OpenMoat` on a disk that ignores case).
//! `openmoat init` is not checked: it is how a person points the hooks at a
//! new binary, and it shows that change.
//!
//! The lock is looked for in the state directory `MOAT_HOME` names and in the
//! default one (`~/.moat`): pointing `MOAT_HOME` at an empty directory must not
//! skip the check, since `uninstall`, `proxy install` and `sandbox sync` act on
//! files outside the state directory. A lock that exists but cannot be read
//! refuses; only a missing one (no `openmoat init` yet) lets the command run.

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::home::{self, Home};
use crate::install::other_name;
use crate::integrity::Lock;

/// The names a person-only command may be started under: the command's and
/// its alias's, exactly.
const NAMES: [&str; 2] = ["openmoat", "moat"];

/// Refuse `command` when a policy lock records a binary and this process runs
/// another file, or was started under another name. Without a lock (no
/// `openmoat init` yet) nothing is recorded.
pub(super) fn refuse_copy(command: &str) -> Result<()> {
    let mut locks: Vec<PathBuf> = Vec::new();
    if let Ok(home) = Home::locate() {
        locks.push(home.lock_path());
    }
    if let Ok(user) = home::user_home() {
        let default = Home::under(&user).lock_path();
        if !locks.contains(&default) {
            locks.push(default);
        }
    }
    let exe = std::env::current_exe().ok();
    let invoked = std::env::args_os().next().map(PathBuf::from);
    check(command, &locks, exe.as_deref(), invoked.as_deref(), |p| {
        std::fs::canonicalize(p).ok()
    })
}

/// [`refuse_copy`] against the locks at `locks`, for the executable `exe`
/// started as `invoked` (`argv[0]`).
fn check(
    command: &str,
    locks: &[PathBuf],
    exe: Option<&Path>,
    invoked: Option<&Path>,
    canonical: impl Fn(&Path) -> Option<PathBuf>,
) -> Result<()> {
    let mut recorded = Vec::new();
    for path in locks {
        match std::fs::read(path) {
            Ok(bytes) => match Lock::parse(&bytes, path) {
                Ok(lock) => recorded.push(PathBuf::from(&lock.binary)),
                Err(error) => bail!(
                    "`{command}` cannot check which binary the policy lock records: {error:#}. \
                     Run `openmoat doctor` from the installed openmoat"
                ),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => bail!(
                "`{command}` cannot read the policy lock {}: {error}. Run it from the \
                 installed openmoat once the lock can be read",
                path.display()
            ),
        }
    }
    if recorded.is_empty() {
        return Ok(());
    }
    let Some(exe) = exe else {
        bail!("`{command}` cannot check which binary is running; run the installed openmoat");
    };
    if !invoked.is_some_and(started_by_name) {
        bail!(
            "`{command}` must be started as `openmoat` (or `moat`), the installed binary's own \
             name; this was started as {}",
            invoked.map_or_else(|| "nothing".into(), |p| p.display().to_string())
        );
    }
    for binary in &recorded {
        if !is_recorded(exe, binary, &canonical) {
            bail!(
                "`{command}` must be run by the installed openmoat, {}; this is {}. Run it from \
                 there, or run `openmoat init` from this binary to point the hooks at it",
                binary.display(),
                exe.display()
            );
        }
    }
    Ok(())
}

/// Whether `invoked`'s file name is one of [`NAMES`], compared exactly, with
/// `.exe` on Windows. `argv[0]` is what the starting process chose, so this
/// only adds to [`is_recorded`]: it refuses a link under another name, or
/// another case of the name on a disk that ignores case, which both resolve
/// to the recorded file.
fn started_by_name(invoked: &Path) -> bool {
    let named = |part: Option<&OsStr>| {
        part.and_then(OsStr::to_str)
            .is_some_and(|n| NAMES.contains(&n))
    };
    let exe = cfg!(windows)
        && invoked
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        && named(invoked.file_stem());
    named(invoked.file_name()) || exe
}

/// Whether `exe` is the same file as `recorded` or its other name, compared by
/// their resolved paths (`canonical`); an unresolvable path matches nothing.
fn is_recorded(exe: &Path, recorded: &Path, canonical: impl Fn(&Path) -> Option<PathBuf>) -> bool {
    let Some(running) = canonical(exe) else {
        return false;
    };
    std::iter::once(recorded.to_path_buf())
        .chain(other_name(recorded))
        .any(|path| canonical(&path).as_ref() == Some(&running))
}

#[cfg(test)]
mod tests;
