//! Whether the running executable is the `openmoat` the policy lock records.
//!
//! A person-only command is refused by name in the guard and by its ancestry
//! here; a copy of the binary under another name, started where the agent is
//! no longer among its ancestors, would get past both. So a person-only command
//! also refuses to run from an executable other than the recorded one, or its
//! `moat` alias. `openmoat init` is not checked: it is how a person points the
//! hooks at a new binary, and it shows that change.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::home::Home;
use crate::install::other_name;
use crate::integrity::Lock;

/// Refuse `command` when a policy lock records a binary and this process runs
/// another file. Without a lock (no `openmoat init` yet) nothing is recorded.
pub(super) fn refuse_copy(command: &str) -> Result<()> {
    let Ok(home) = Home::locate() else {
        return Ok(());
    };
    let Ok(lock) = Lock::load(&home.lock_path()) else {
        return Ok(());
    };
    let Ok(exe) = std::env::current_exe() else {
        bail!("`{command}` cannot check which binary is running; run the installed openmoat");
    };
    let recorded = PathBuf::from(&lock.binary);
    if is_recorded(&exe, &recorded, |p| std::fs::canonicalize(p).ok()) {
        return Ok(());
    }
    bail!(
        "`{command}` must be run by the installed openmoat, {}; this is {}. Run it from \
         there, or run `openmoat init` from this binary to point the hooks at it",
        recorded.display(),
        exe.display()
    )
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
mod tests {
    use super::*;

    /// A fake filesystem: each path resolves to the file named in `links`.
    fn resolver<'a>(links: &'a [(&'a str, &'a str)]) -> impl Fn(&Path) -> Option<PathBuf> + 'a {
        move |p: &Path| {
            links
                .iter()
                .find(|(from, _)| Path::new(from) == p)
                .map(|(_, to)| PathBuf::from(to))
        }
    }

    #[test]
    fn the_recorded_binary_and_its_links_are_recorded() {
        let fs = resolver(&[
            (
                "/usr/local/bin/openmoat",
                "/opt/cellar/openmoat/0.9.0/bin/openmoat",
            ),
            (
                "/opt/cellar/openmoat/0.9.0/bin/openmoat",
                "/opt/cellar/openmoat/0.9.0/bin/openmoat",
            ),
        ]);
        let recorded = Path::new("/usr/local/bin/openmoat");
        assert!(is_recorded(recorded, recorded, &fs));
        assert!(is_recorded(
            Path::new("/opt/cellar/openmoat/0.9.0/bin/openmoat"),
            recorded,
            &fs
        ));
    }

    #[test]
    fn the_moat_alias_beside_the_recorded_binary_counts() {
        let fs = resolver(&[
            ("/usr/local/bin/openmoat", "/usr/local/bin/openmoat"),
            ("/usr/local/bin/moat", "/usr/local/bin/moat"),
        ]);
        assert!(is_recorded(
            Path::new("/usr/local/bin/moat"),
            Path::new("/usr/local/bin/openmoat"),
            &fs
        ));
    }

    #[test]
    fn a_copy_or_a_renamed_binary_is_not_the_recorded_one() {
        let fs = resolver(&[
            ("/usr/local/bin/openmoat", "/usr/local/bin/openmoat"),
            ("/tmp/x", "/tmp/x"),
            ("/tmp/link", "/tmp/x"),
        ]);
        let recorded = Path::new("/usr/local/bin/openmoat");
        assert!(!is_recorded(Path::new("/tmp/x"), recorded, &fs));
        assert!(!is_recorded(Path::new("/tmp/link"), recorded, &fs));
    }

    #[test]
    fn a_path_that_does_not_resolve_matches_nothing() {
        let fs = resolver(&[("/usr/local/bin/openmoat", "/usr/local/bin/openmoat")]);
        assert!(!is_recorded(
            Path::new("/gone/openmoat"),
            Path::new("/usr/local/bin/openmoat"),
            &fs
        ));
        assert!(!is_recorded(
            Path::new("/usr/local/bin/openmoat"),
            Path::new("/gone"),
            &fs
        ));
    }
}
