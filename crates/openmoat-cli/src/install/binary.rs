//! Which path the hooks run: the stable install path, not the versioned file.
//!
//! Package managers install into versioned directories and point a stable link
//! at the current one: Homebrew (`<prefix>/bin/moat` → `<prefix>/Cellar/moat/<v>/bin/moat`),
//! Scoop (`apps/moat/current` → `apps/moat/<v>`), Nix profiles. `current_exe()` can
//! return the versioned file, which an upgrade deletes; a hook naming it then
//! fails to start and the host proceeds (fail open). `init` records the stable
//! path instead, and only when it resolves to the very file that is running
//! (ADR-016).

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result};

/// The path hooks and the lock record for the running `openmoat`.
pub fn hook_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the openmoat binary")?;
    let invoked = std::env::args_os()
        .next()
        .and_then(|arg0| invoked_path(&arg0));
    Ok(choose(&exe, invoked.as_deref(), |p| {
        fs::canonicalize(p).ok()
    }))
}

/// The binary a hook command names, judged against the running one, as the
/// fix a person should apply.
pub fn stale_hint(command: &str) -> String {
    let running = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());
    match fs::canonicalize(command) {
        Err(_) => format!("hook runs {command}, which does not exist; run `openmoat init`"),
        Ok(target) if Some(&target) != running.as_ref() => format!(
            "hook runs {command}, a different OpenMoat binary than this one; run `openmoat init` \
             with the openmoat hooks should use"
        ),
        // This binary, so what differs is the entry itself: an older release
        // wrote it with fewer tools, another timeout, or without one of its events.
        Ok(_) => format!(
            "hook entry for {command} is out of date (written by an older OpenMoat); run `openmoat init`"
        ),
    }
}

/// The command's name before the rename, still installed beside `openmoat`
/// for a few releases (the `moat` binary starts the `openmoat` next to it).
const ALIAS: &str = "moat";
/// The command's name.
const NAME: &str = "openmoat";

/// `binary`'s file name with `name` in place of its stem, keeping `.exe`;
/// `None` unless the stem is `from`.
fn renamed(binary: &Path, from: &str, name: &str) -> Option<PathBuf> {
    if binary.file_stem()? != from {
        return None;
    }
    let mut file = name.to_owned();
    if let Some(ext) = binary.extension() {
        file.push('.');
        file.push_str(ext.to_str()?);
    }
    Some(binary.with_file_name(file))
}

/// The `moat` alias of `binary` (`<dir>/moat` for `<dir>/openmoat`) when it
/// is installed with it: both resolve into the same directory, as one install
/// puts them. Hooks written before the rename run it.
pub fn alias_of(binary: &Path) -> Option<PathBuf> {
    let alias = renamed(binary, NAME, ALIAS)?;
    let dir = |p: &Path| fs::canonicalize(p).ok()?.parent().map(Path::to_path_buf);
    (dir(&alias)? == dir(binary)?).then_some(alias)
}

/// The other name of `binary` in its directory, whether or not it exists:
/// `<dir>/moat` for `<dir>/openmoat` and the reverse. Either one runs the
/// hooks, so both are protected.
pub fn other_name(binary: &Path) -> Option<PathBuf> {
    renamed(binary, NAME, ALIAS).or_else(|| renamed(binary, ALIAS, NAME))
}

/// First of: the package manager's stable link, the path this process was
/// invoked by, the executable itself, that resolves (`canonical`) to the same
/// file as `exe`. Never a path that reaches another file or none.
fn choose(
    exe: &Path,
    invoked: Option<&Path>,
    canonical: impl Fn(&Path) -> Option<PathBuf>,
) -> PathBuf {
    let Some(real) = canonical(exe) else {
        return exe.to_path_buf();
    };
    // Windows `canonicalize` adds a `\\?\` prefix a hook command should not carry.
    let plain = PathBuf::from(crate::context::strip_verbatim(&real.to_string_lossy()));
    [
        stable_link(&plain),
        stable_link(exe),
        invoked.map(Path::to_path_buf),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| canonical(candidate).as_ref() == Some(&real))
    .unwrap_or_else(|| exe.to_path_buf())
}

/// The stable link a versioned install is reached by, lexically:
/// `<prefix>/Cellar/<name>/<version>/<rest>` → `<prefix>/<rest>` (Homebrew,
/// Linuxbrew) and `…/apps/<name>/<version>/<rest>` → `…/apps/<name>/current/<rest>`
/// (Scoop). Unrelated paths that happen to match are discarded by the caller's
/// same-file check.
fn stable_link(exe: &Path) -> Option<PathBuf> {
    let parts: Vec<Component> = exe.components().collect();
    let at = parts
        .iter()
        .position(|c| matches!(c.as_os_str().to_str(), Some("Cellar" | "apps")))?;
    let (version, rest) = (parts.get(at + 2)?, parts.get(at + 3..)?);
    if rest.is_empty() || version.as_os_str() == "current" {
        return None;
    }
    let mut link: PathBuf = if parts[at].as_os_str() == "Cellar" {
        parts[..at].iter().collect()
    } else {
        let mut link: PathBuf = parts[..at + 2].iter().collect();
        link.push("current");
        link
    };
    link.extend(rest);
    Some(link)
}

/// `argv[0]` as a path: absolute or relative to the working directory when it
/// names a directory, otherwise looked up in `PATH` like the shell did.
fn invoked_path(arg0: &std::ffi::OsStr) -> Option<PathBuf> {
    let arg0 = Path::new(arg0);
    if arg0.components().count() > 1 {
        return std::path::absolute(arg0).ok();
    }
    let dirs: Vec<PathBuf> = std::env::split_paths(&std::env::var_os("PATH")?).collect();
    crate::environment::find_in(&dirs, &[], arg0.to_str()?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A filesystem where each listed path resolves to the given real file.
    fn fs_of(links: &[(&str, &str)]) -> impl Fn(&Path) -> Option<PathBuf> + use<> {
        let map: BTreeMap<PathBuf, PathBuf> = links
            .iter()
            .map(|(p, r)| (PathBuf::from(p), PathBuf::from(r)))
            .collect();
        move |p| map.get(p).cloned()
    }

    const CELLAR: &str = "/opt/homebrew/Cellar/moat/0.1.0/bin/moat";

    #[test]
    fn homebrew_cellar_path_becomes_the_prefix_bin_link() {
        let fs = fs_of(&[(CELLAR, CELLAR), ("/opt/homebrew/bin/moat", CELLAR)]);
        let chosen = choose(Path::new(CELLAR), Some(Path::new("moat-typo")), fs);
        assert_eq!(chosen, Path::new("/opt/homebrew/bin/moat"));
    }

    #[test]
    fn a_stable_link_that_reaches_another_file_is_never_written() {
        let other = "/opt/homebrew/Cellar/moat/0.2.0/bin/moat";
        let fs = fs_of(&[(CELLAR, CELLAR), ("/opt/homebrew/bin/moat", other)]);
        assert_eq!(choose(Path::new(CELLAR), None, &fs), Path::new(CELLAR));
        let fs = fs_of(&[(CELLAR, CELLAR)]);
        assert_eq!(
            choose(Path::new(CELLAR), None, fs),
            Path::new(CELLAR),
            "dangling link"
        );
    }

    #[test]
    fn invocation_path_is_used_when_it_reaches_the_running_file() {
        let store = "/nix/store/abc-moat/bin/moat";
        let profile = "/home/u/.nix-profile/bin/moat";
        let fs = fs_of(&[
            (store, store),
            (profile, store),
            ("/tmp/evil/moat", "/tmp/evil/moat"),
        ]);
        assert_eq!(
            choose(Path::new(store), Some(Path::new(profile)), &fs),
            Path::new(profile)
        );
        let planted = Some(Path::new("/tmp/evil/moat"));
        assert_eq!(choose(Path::new(store), planted, fs), Path::new(store));
    }

    #[test]
    fn plain_installs_keep_the_executable_path() {
        let cargo = "/home/u/.cargo/bin/moat";
        let fs = fs_of(&[(cargo, cargo)]);
        assert_eq!(
            choose(Path::new(cargo), Some(Path::new(cargo)), &fs),
            Path::new(cargo)
        );
        assert_eq!(
            choose(Path::new("/gone/moat"), None, fs),
            Path::new("/gone/moat")
        );
    }

    #[test]
    fn versioned_layouts_map_to_their_stable_link() {
        // Compared as paths, so the expectation holds with `\` separators too.
        let link = |p: &str| stable_link(Path::new(p));
        let some = |p: &str| Some(PathBuf::from(p));
        assert_eq!(link(CELLAR), some("/opt/homebrew/bin/moat"));
        assert_eq!(
            link("/home/linuxbrew/.linuxbrew/Cellar/moat/1.2/bin/moat"),
            some("/home/linuxbrew/.linuxbrew/bin/moat")
        );
        assert_eq!(
            link("/c/Users/u/scoop/apps/moat/0.1.0/moat.exe"),
            some("/c/Users/u/scoop/apps/moat/current/moat.exe")
        );
        assert_eq!(link("/c/Users/u/scoop/apps/moat/current/moat.exe"), None);
        assert_eq!(link("/opt/homebrew/Cellar/moat/0.1.0"), None);
        assert_eq!(link("/home/u/.cargo/bin/moat"), None);
    }

    #[test]
    fn each_name_has_the_other_beside_it() {
        let other = |p: &str| other_name(Path::new(p));
        assert_eq!(other("/u/bin/openmoat"), Some(PathBuf::from("/u/bin/moat")));
        assert_eq!(other("/u/bin/moat"), Some(PathBuf::from("/u/bin/openmoat")));
        assert_eq!(
            other("/c/scoop/apps/openmoat/current/openmoat.exe"),
            Some(PathBuf::from("/c/scoop/apps/openmoat/current/moat.exe"))
        );
        assert_eq!(other("/opt/t/moatd"), None);
        assert_eq!(other("/u/bin/openmoat-dev"), None);
    }

    #[test]
    fn the_alias_counts_only_when_installed_with_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let binary = bin.join("openmoat");
        fs::write(&binary, b"").unwrap();
        assert_eq!(alias_of(&binary), None, "no alias installed");
        fs::write(bin.join("moat"), b"").unwrap();
        assert_eq!(alias_of(&binary), Some(bin.join("moat")));
        #[cfg(unix)]
        {
            // `bin/moat` reaching another package's file is not ours.
            let elsewhere = dir.path().join("other/moat");
            fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
            fs::write(&elsewhere, b"").unwrap();
            fs::remove_file(bin.join("moat")).unwrap();
            std::os::unix::fs::symlink(&elsewhere, bin.join("moat")).unwrap();
            assert_eq!(alias_of(&binary), None);
        }
        assert_eq!(
            alias_of(&bin.join("moat")),
            None,
            "only openmoat has an alias"
        );
    }
}
