//! Project root discovery: the nearest ancestor that is a git work tree.
//!
//! The project root is what `${project}` names, and the default policy lets an
//! agent read and write everywhere under it. A root that is the home directory,
//! one of its ancestors or a filesystem root would turn that into "everywhere
//! in the home directory" (`~/.gitconfig`, `~/Library/LaunchAgents`), so such
//! a root is refused and the session has no project: `${project}` patterns
//! match nothing and those calls fall through to `ask` and the defaults.

use std::path::{Path, PathBuf};

use crate::context::{CASE_INSENSITIVE_PATHS, absolute, path_string};

/// Walk up from `start` to the first directory containing `.git` (a
/// directory, or the file git uses for worktrees). Falls back to `start` when
/// there is none, or when it is one that may not be trusted ([`trusted`]),
/// such as a dotfiles repository in the home directory. `None` when `start`
/// may not be trusted either.
pub fn root_of(start: &Path, home: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .into_iter()
        .chain([start])
        .find(|root| trusted(root, home))
        .map(Path::to_path_buf)
}

/// A project root is never a filesystem root (`/`, `C:\`, a UNC share), the
/// home directory or an ancestor of it. Compared as written and canonically,
/// so a link to the home directory is refused too.
pub fn trusted(root: &Path, home: &Path) -> bool {
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    root.parent().is_some()
        && !contains(root, home)
        && !matches!((canonical(root), canonical(home)), (Some(r), Some(h)) if contains(&r, &h))
}

/// `dir` is `path` or one of its ancestors, after removing `.` and `..`.
pub fn contains(dir: &Path, path: &Path) -> bool {
    let fold = |p: &Path| {
        let s = path_string(&absolute(p).unwrap_or_else(|_| p.to_path_buf()));
        let s = s.trim_end_matches('/').to_owned();
        if CASE_INSENSITIVE_PATHS {
            s.to_lowercase()
        } else {
            s
        }
    };
    let (dir, path) = (fold(dir), fold(path));
    path == dir
        || path
            .strip_prefix(&dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::{root_of, trusted};

    #[test]
    fn finds_git_root_or_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let repo = dir.path().join("repo");
        let nested = repo.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(root_of(&nested, &home), Some(nested.clone()));
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(root_of(&nested, &home), Some(repo.clone()));
        std::fs::remove_dir(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git"), "gitdir: ../main/.git/worktrees/x").unwrap();
        assert_eq!(root_of(&nested, &home), Some(repo));
    }

    #[test]
    fn home_its_ancestors_and_roots_are_never_the_project() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("code/app")).unwrap();
        assert_eq!(root_of(&home, &home), None, "no repository, cwd = home");
        assert_eq!(root_of(dir.path(), &home), None, "ancestor of home");
        let root = dir.path().ancestors().last().unwrap();
        assert_eq!(root_of(root, &home), None, "filesystem root");
        let app = home.join("code/app");
        assert_eq!(root_of(&app, &home), Some(app.clone()));
        std::fs::create_dir(home.join(".git")).unwrap();
        assert_eq!(
            root_of(&app, &home),
            Some(app),
            "a dotfiles repository in home"
        );
        assert_eq!(root_of(&home, &home), None);
        assert!(!trusted(&home.join("code/.."), &home));
        assert!(trusted(&dir.path().join("homework"), &home));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_home_is_not_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        assert_eq!(root_of(&link, &home), None);
        assert!(!trusted(std::path::Path::new("/"), &home));
    }
}
