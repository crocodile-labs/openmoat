//! The state directory a hook names on its command line (ADR-071).
//!
//! `openmoat init` writes `--home <state directory>` into every hook it
//! installs, and the lock pins the hook file that holds it. The guard takes
//! its state directory from that argument and not from `MOAT_HOME`: the
//! environment is what the host hands its hooks, and a host that builds it
//! from a file or setting OpenMoat does not guard could point the guard at a
//! state directory, policy and lock of anyone's choosing. A `MOAT_HOME` that
//! names another directory than the argument is refused: the guard denies.
//!
//! [`pin`] is called once, first thing in `openmoat guard`; from then on
//! [`super::Home::locate`] returns the pinned directory, so every part of the
//! guard (the budget's deny, the record, the heartbeat) uses it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context as _, Result, bail};

static PINNED: OnceLock<PathBuf> = OnceLock::new();

/// The directory [`pin`] set, if any.
pub(super) fn pinned() -> Option<&'static Path> {
    PINNED.get().map(PathBuf::as_path)
}

/// `path` as a hook command names it: `/`-separated, without Windows'
/// verbatim prefix, so [`openmoat_hosts::encode_home`] keeps it readable.
pub fn arg_form(path: &Path) -> String {
    crate::context::path_string(path)
}

/// The state directory `word` (the guard's `--home`) names, checked against
/// `env` (the `MOAT_HOME` the guard was given); an error when the word does
/// not name an absolute directory, or `env` names another one.
pub fn checked(word: &str, env: Option<&OsStr>) -> Result<PathBuf> {
    let Some(dir) = openmoat_hosts::decode_home(word) else {
        bail!("the hook's `--home {word}` is not a state directory OpenMoat writes");
    };
    let dir = PathBuf::from(dir);
    if !dir.is_absolute() {
        bail!(
            "the hook's `--home {}` is not an absolute path",
            dir.display()
        );
    }
    if let Some(env) = env.filter(|v| !v.is_empty()) {
        let named = Path::new(env);
        if !same_dir(&dir, named) {
            bail!(
                "the hook names the state directory {} but its environment sets {}={}; the \
                 hook's command line decides, so the call is refused: remove {} from the \
                 agent's settings, or run `openmoat init` with the {} you mean",
                dir.display(),
                super::ENV,
                named.display(),
                super::ENV,
                super::ENV,
            );
        }
    }
    Ok(dir)
}

/// [`checked`], then make it the state directory of this process.
pub fn pin(word: &str, env: Option<&OsStr>) -> Result<()> {
    let dir = checked(word, env)?;
    match PINNED.get() {
        Some(already) if *already == dir => Ok(()),
        Some(already) => bail!(
            "the state directory is already {}, not {}",
            already.display(),
            dir.display()
        ),
        None => PINNED.set(dir).ok().context("pinning the state directory"),
    }
}

/// Whether `a` and `b` name one directory: the same canonical path where both
/// resolve, else the same path written with `/` and no trailing separator (a
/// sandbox may refuse to resolve them; spelled differently they differ).
fn same_dir(a: &Path, b: &Path) -> bool {
    if let (Ok(a), Ok(b)) = (a.canonicalize(), b.canonicalize()) {
        return a == b;
    }
    let plain = |p: &Path| arg_form(p).trim_end_matches('/').to_owned();
    plain(a) == plain(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_argument_decides_and_a_matching_or_absent_variable_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state dir");
        std::fs::create_dir(&root).unwrap();
        let word = openmoat_hosts::encode_home(&arg_form(&root));
        assert_eq!(
            checked(&word, None).unwrap(),
            PathBuf::from(arg_form(&root))
        );
        assert!(checked(&word, Some(OsStr::new(""))).is_ok());
        assert!(checked(&word, Some(root.as_os_str())).is_ok());
        let slashed = format!("{}/", root.display());
        assert!(checked(&word, Some(OsStr::new(&slashed))).is_ok());
    }

    #[test]
    fn another_directory_in_the_variable_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (real, other) = (dir.path().join("real"), dir.path().join("other"));
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&other).unwrap();
        let word = openmoat_hosts::encode_home(&arg_form(&real));
        let error = checked(&word, Some(other.as_os_str())).unwrap_err();
        assert!(format!("{error:#}").contains("MOAT_HOME="), "{error:#}");
        // A directory that does not exist is told apart by its spelling.
        let missing = dir.path().join("missing");
        assert!(checked(&word, Some(missing.as_os_str())).is_err());
    }

    #[test]
    fn a_relative_or_malformed_argument_is_refused() {
        for word in ["relative/.moat", "/a b", "/a+zz", ""] {
            assert!(checked(word, None).is_err(), "{word}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_the_same_directory_is_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let word = openmoat_hosts::encode_home(&arg_form(&real));
        assert!(checked(&word, Some(link.as_os_str())).is_ok());
    }
}
