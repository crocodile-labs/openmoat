//! Symlink resolution of action paths for the engine (`openmoat_core::PathResolver`).
//!
//! `moat guard` checks every path a tool call reads or writes where it really
//! points as well as where it was written, so `cat ./s/id_rsa` after
//! `ln -s ~/.ssh ./s` meets the `~/.ssh/**` deny. Resolution happens at
//! decision time; a link swapped afterwards is out of reach until OS
//! enforcement exists (ADR-009). It also lists the directories an unquoted
//! glob operand (`cat .en?`) searches, so the files the shell would pass are
//! checked too.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::PathResolver;

use crate::context::path_string;

/// Dangling links followed before giving up. It is above every OS's own limit
/// (macOS 32, Linux 40, Windows 63): a write through a dangling link creates
/// the link's target, so a chain the OS still follows must be resolved to its
/// end. A chain longer than this one the OS refuses too (`ELOOP`).
const MAX_LINK_HOPS: u8 = 64;

/// Where a path really points ([`FsPathResolver::resolution`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The path is itself: no symlink on the way.
    Itself,
    /// The path reaches this other path through a symlink.
    Elsewhere(String),
    /// Where it points is unknown: a link loop, or a chain past
    /// `MAX_LINK_HOPS`. Never to be taken as the path itself.
    Unresolvable,
}

/// Resolves through the real filesystem. The policy is compiled for the
/// resolved spellings of the project and home roots too (`context.rs`), so a
/// project under a symlinked directory (macOS `/tmp` → `/private/tmp`) still
/// matches `${project}/**` once its paths are resolved.
#[derive(Debug)]
pub struct FsPathResolver;

impl FsPathResolver {
    /// Where `path` really points, telling a path that is itself apart from
    /// one that cannot be resolved, which [`PathResolver::resolve`] reports
    /// alike (`None`): the engine still checks the literal path then, but a
    /// check that a path still resolves where it did must not pass.
    #[must_use]
    pub fn resolution(path: &str) -> Resolution {
        match real_path(Path::new(path), MAX_LINK_HOPS) {
            None => Resolution::Unresolvable,
            Some(real) => {
                let real = path_string(&real);
                if real == path {
                    Resolution::Itself
                } else {
                    Resolution::Elsewhere(real)
                }
            }
        }
    }
}

impl PathResolver for FsPathResolver {
    fn resolve(&self, path: &str) -> Option<String> {
        match Self::resolution(path) {
            Resolution::Elsewhere(real) => Some(real),
            Resolution::Itself | Resolution::Unresolvable => None,
        }
    }

    /// Follows links, as the shell's glob does; a name that is not UTF-8 is
    /// checked in its lossy spelling.
    fn read_dir(&self, dir: &str) -> Vec<String> {
        fs::read_dir(dir).map_or_else(
            |_| Vec::new(),
            |entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            },
        )
    }
}

/// Canonical form of `path`. A path that does not exist resolves through its
/// deepest existing ancestor; a dangling symlink through its target. A root is
/// kept as written: it cannot be a link, and on Windows `canonicalize("/")`
/// would turn a drive-less path into one on the current drive.
fn real_path(path: &Path, hops: u8) -> Option<PathBuf> {
    if path.parent().is_none() {
        return Some(path.to_path_buf());
    }
    if let Ok(real) = fs::canonicalize(path) {
        return Some(real);
    }
    let parent = path.parent()?;
    if let Ok(target) = fs::read_link(path) {
        return real_path(&parent.join(target), hops.checked_sub(1)?);
    }
    Some(real_path(parent, hops)?.join(path.file_name()?))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn missing_paths_keep_their_root() {
        assert_eq!(
            FsPathResolver.resolve("/moat-missing-root/src/lib.rs"),
            None
        );
    }

    /// A home with a project in it, under a temporary directory with its own
    /// links (macOS `/var` → `/private/var`) resolved: `(dir, home, project)`.
    #[cfg(unix)]
    fn setup() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(dir.path()).unwrap().join("home");
        let project = home.join("proj");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(home.join(".ssh/id_rsa"), "key").unwrap();
        (dir, path_string(&home), path_string(&project))
    }

    #[cfg(unix)]
    #[test]
    fn plain_paths_inside_the_project_resolve_to_themselves() {
        let (_dir, _, p) = setup();
        let r = FsPathResolver;
        assert_eq!(r.resolve(&format!("{p}/src")), None);
        assert_eq!(r.resolve(&format!("{p}/src/new/file.rs")), None);
    }

    #[cfg(unix)]
    #[test]
    fn linked_directories_and_files_resolve_to_their_target() {
        let (_dir, h, p) = setup();
        let r = FsPathResolver;
        symlink(format!("{h}/.ssh"), format!("{p}/s")).unwrap();
        assert_eq!(
            r.resolve(&format!("{p}/s/id_rsa")),
            Some(format!("{h}/.ssh/id_rsa"))
        );
        assert_eq!(
            r.resolve(&format!("{p}/s/authorized_keys")),
            Some(format!("{h}/.ssh/authorized_keys")),
            "a file that does not exist yet resolves through its directory"
        );
        symlink("../.ssh/known_hosts", format!("{p}/k")).unwrap();
        assert_eq!(
            r.resolve(&format!("{p}/k")),
            Some(format!("{h}/.ssh/known_hosts")),
            "a dangling relative link resolves through its target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn directories_list_their_names_through_links() {
        let (_dir, h, p) = setup();
        symlink(format!("{h}/.ssh"), format!("{p}/s")).unwrap();
        let mut names = FsPathResolver.read_dir(&p);
        names.sort();
        assert_eq!(names, ["s", "src"]);
        assert_eq!(FsPathResolver.read_dir(&format!("{p}/s")), ["id_rsa"]);
        assert!(
            FsPathResolver
                .read_dir(&format!("{h}/.ssh/id_rsa"))
                .is_empty()
        );
        assert!(FsPathResolver.read_dir(&format!("{p}/missing")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn link_loops_give_up() {
        let (_dir, _, p) = setup();
        let r = FsPathResolver;
        symlink(format!("{p}/b"), format!("{p}/a")).unwrap();
        symlink(format!("{p}/a"), format!("{p}/b")).unwrap();
        assert_eq!(r.resolve(&format!("{p}/a")), None);
        assert_eq!(
            FsPathResolver::resolution(&format!("{p}/a")),
            Resolution::Unresolvable
        );
        assert_eq!(
            FsPathResolver::resolution(&format!("{p}/src")),
            Resolution::Itself
        );
    }

    /// A chain of dangling links `{p}/l0` → `{p}/l1` → … → `{p}/l{n-1}` → `target`.
    #[cfg(unix)]
    fn chain(p: &str, n: usize, target: &str) -> String {
        for i in 0..n {
            let to = if i + 1 == n {
                target.to_owned()
            } else {
                format!("{p}/l{}", i + 1)
            };
            symlink(to, format!("{p}/l{i}")).unwrap();
        }
        format!("{p}/l0")
    }

    /// The OS follows a dangling chain of up to 32 (macOS) or 40 (Linux) links
    /// and a write creates its target, so a chain that long resolves to it.
    #[cfg(unix)]
    #[test]
    fn long_dangling_chains_resolve_to_their_end() {
        let (_dir, h, p) = setup();
        let keys = format!("{h}/.ssh/authorized_keys");
        let start = chain(&p, 40, &keys);
        assert_eq!(FsPathResolver.resolve(&start), Some(keys.clone()));
        assert_eq!(
            FsPathResolver::resolution(&start),
            Resolution::Elsewhere(keys)
        );
    }

    /// The default policy, through this resolver, denies a write through a
    /// 12-link dangling chain from the project into `~/.ssh`.
    #[cfg(unix)]
    #[test]
    fn the_default_policy_denies_a_write_through_a_long_chain() {
        use openmoat_core::{Action, CompiledPolicy, EvalContext, NoResolver, Policy, Verdict};
        let (_dir, h, p) = setup();
        let start = chain(&p, 12, &format!("{h}/.ssh/authorized_keys"));
        let policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
        let ctx = EvalContext {
            home: h.clone(),
            project: Some(p.clone()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: p.clone(),
            case_insensitive_paths: false,
        };
        let compiled = CompiledPolicy::compile(&policy, &ctx).unwrap();
        let write = Action::FsWrite { path: start };
        let decision = compiled.decide_with(&write, &NoResolver, &FsPathResolver);
        assert_eq!(decision.verdict, Verdict::Deny, "{decision:?}");
        let plain = Action::FsWrite {
            path: format!("{p}/src/lib.rs"),
        };
        let decision = compiled.decide_with(&plain, &NoResolver, &FsPathResolver);
        assert_ne!(decision.verdict, Verdict::Deny, "{decision:?}");
    }

    /// A chain past the limit is unresolvable, never the path itself.
    #[cfg(unix)]
    #[test]
    fn a_chain_past_the_limit_is_unresolvable() {
        let (_dir, h, p) = setup();
        let start = chain(&p, usize::from(MAX_LINK_HOPS) + 2, &format!("{h}/.ssh/x"));
        assert_eq!(FsPathResolver::resolution(&start), Resolution::Unresolvable);
        assert_eq!(FsPathResolver.resolve(&start), None);
    }
}
