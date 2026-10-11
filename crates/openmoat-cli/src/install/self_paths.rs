//! The `moat` binary every hook runs, protected by the path it was recorded
//! at. The default policy's `**/bin/moat` glob misses a binary installed under
//! another name or prefix (`target/release/moat`, `/opt/tools/moatd`), and on
//! Linux Claude Code drops every glob write deny, so the recorded path, the
//! file it resolves to and the directory holding that file are added as
//! literal `kernel-self` paths when a call is decided.
//!
//! The host sandboxes are written once for many sessions, so they get only
//! what a package upgrade leaves in place ([`sandbox_paths`]): the recorded
//! path and its directory, also with that directory's links resolved. A link
//! as the binary itself (Homebrew's `bin/moat` → `Cellar/moat/<version>/…`)
//! points somewhere new after each upgrade; its target is left to the hook.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_core::{Policy, RuleGroup};

use crate::context::{absolute, path_string};
use crate::home::Home;
use crate::integrity::Lock;

/// The rule the binary's paths join.
const KERNEL_SELF: &str = "kernel-self";

/// The binary the lock recorded, or the running one before there is a lock.
pub fn recorded_binary(home: &Home) -> Result<PathBuf> {
    match Lock::load(&home.lock_path()) {
        Ok(lock) => Ok(PathBuf::from(lock.binary)),
        Err(_) => super::hook_binary(),
    }
}

/// `binary` as recorded and its directory, each also with the directory's
/// links resolved, in the slash-separated form the policy uses.
pub fn sandbox_paths(binary: &Path) -> Vec<String> {
    let recorded = absolute(binary).unwrap_or_else(|_| binary.to_path_buf());
    let mut paths = vec![recorded.clone()];
    if let (Some(dir), Some(name)) = (recorded.parent(), recorded.file_name()) {
        paths.push(dir.to_path_buf());
        if let Ok(real) = fs::canonicalize(dir) {
            paths.push(real.join(name));
            paths.push(real);
        }
    }
    literal(&paths)
}

/// [`sandbox_paths`], and the file `binary` resolves to and that file's
/// directory: what a call is decided against.
pub fn protected_paths(binary: &Path) -> Vec<String> {
    let mut paths: Vec<PathBuf> = sandbox_paths(binary).iter().map(PathBuf::from).collect();
    if let Ok(target) = fs::canonicalize(binary) {
        paths.extend(target.parent().map(Path::to_path_buf));
        paths.push(target);
    }
    literal(&paths)
}

/// Add the paths of the binary the lock recorded to `policy` ([`protect`]).
pub fn protect_recorded(home: &Home, policy: &mut Policy) -> Result<()> {
    protect(policy, &protected_paths(&recorded_binary(home)?));
    Ok(())
}

/// `paths` in slash form, deduplicated, without a spelling with glob syntax:
/// as a pattern it would name other files ([`refuse_writable`] keeps `init`
/// from recording one).
fn literal(paths: &[PathBuf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in paths.iter().map(|p| path_string(p)) {
        if !has_glob_syntax(&path) && !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// Add `paths` to the `kernel-self` deny rule's writes, creating the rule
/// when the policy has none: the binary is protected whatever the policy says.
pub fn protect(policy: &mut Policy, paths: &[String]) {
    let index = if let Some(index) = policy.deny.iter().position(|g| g.id == KERNEL_SELF) {
        index
    } else {
        policy.deny.push(RuleGroup {
            id: KERNEL_SELF.to_owned(),
            reason: Some("the moat binary every installed hook runs".to_owned()),
            ..RuleGroup::default()
        });
        policy.deny.len() - 1
    };
    let writes = &mut policy.deny[index].fs_write;
    for path in paths {
        if !writes.contains(path) {
            writes.push(path.clone());
        }
    }
}

/// Refuse to record a binary an agent could replace: one inside the project
/// of the current directory, a temp directory, or any of `writable` (the
/// directories the host sandboxes let commands write). Every hook would run
/// whatever an agent left there.
pub fn refuse_writable(binary: &Path, writable: &[String]) -> Result<()> {
    let target = fs::canonicalize(binary).ok();
    for path in std::iter::once(binary).chain(target.as_deref()) {
        if has_glob_syntax(&path_string(path)) {
            bail!(
                "refusing to set up hooks for {}: the path has glob characters (`*?[]{{}}`), \
                 so no sandbox can protect it by name; install moat where the path has none",
                path.display()
            );
        }
    }
    let mut places: Vec<(PathBuf, &str)> = Vec::new();
    let cwd = std::env::current_dir()?;
    if let Some(project) = crate::project::root_of(&cwd, &crate::home::user_home()?) {
        places.push((project, "inside the project of the current directory"));
    }
    for dir in temp_dirs() {
        places.push((dir, "in a temp directory"));
    }
    let sandboxed = "in a directory the agents' sandboxes may write";
    places.extend(writable.iter().map(|dir| (PathBuf::from(dir), sandboxed)));
    for (place, why) in &places {
        let real = fs::canonicalize(place).ok();
        let under = |path: &Path| {
            std::iter::once(place)
                .chain(&real)
                .any(|dir| crate::project::contains(dir, path))
        };
        if std::iter::once(binary).chain(target.as_deref()).any(under) {
            bail!(
                "refusing to set up hooks for {}: it is {why} ({}), where an agent could \
                 replace the binary every hook runs; install moat outside it (for example with \
                 `cargo install`, Homebrew or the release installer) and run that moat's `init`",
                binary.display(),
                place.display()
            );
        }
    }
    Ok(())
}

/// The temp directories commands may write: this process's and, on Unix,
/// `/tmp`, which sandboxed tools often use whatever `TMPDIR` says.
fn temp_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![std::env::temp_dir()];
    if cfg!(unix) {
        dirs.push(PathBuf::from("/tmp"));
    }
    dirs
}

fn has_glob_syntax(path: &str) -> bool {
    path.contains(['*', '?', '[', ']', '{', '}'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_see_the_link_target_and_sandboxes_what_an_upgrade_keeps() {
        let dir = tempfile::tempdir().unwrap();
        let real = fs::canonicalize(dir.path()).unwrap();
        let target = real.join("release/moat-dev");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"").unwrap();
        let release = path_string(&real.join("release"));
        assert_eq!(
            sandbox_paths(&target),
            [path_string(&target), release.clone()]
        );
        assert_eq!(protected_paths(&target), sandbox_paths(&target));
        #[cfg(unix)]
        {
            let link = real.join("bin/kernel");
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let bin = path_string(&real.join("bin"));
            assert_eq!(sandbox_paths(&link), [path_string(&link), bin.clone()]);
            assert_eq!(
                protected_paths(&link),
                [path_string(&link), bin, release, path_string(&target)]
            );
        }
        assert!(protected_paths(&real.join("a[1]/moat")).is_empty());
        let refused = refuse_writable(&real.join("a*/moat"), &[]).unwrap_err();
        assert!(refused.to_string().contains("glob characters"), "{refused}");
    }

    #[test]
    fn protect_joins_kernel_self_once_or_creates_it() {
        let paths = vec!["/opt/t/moatd".to_owned(), "/opt/t".to_owned()];
        let mut policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
        let before = policy.deny.len();
        protect(&mut policy, &paths);
        protect(&mut policy, &paths);
        assert_eq!(policy.deny.len(), before);
        let group = policy.deny.iter().find(|g| g.id == KERNEL_SELF).unwrap();
        let count = |p: &str| group.fs_write.iter().filter(|w| *w == p).count();
        assert_eq!((count("/opt/t/moatd"), count("/opt/t")), (1, 1));

        let mut bare = Policy::parse("version: 1\n").unwrap();
        protect(&mut bare, &paths);
        assert_eq!(bare.deny[0].id, KERNEL_SELF);
        assert_eq!(bare.deny[0].fs_write, paths);
        bare.lint().unwrap();
    }
}
