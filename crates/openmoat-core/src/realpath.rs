//! Symlink resolution of action paths, supplied by the caller.
//!
//! Policy patterns name locations (`~/.ssh/**`, `${project}/**`), but a path an
//! agent writes can reach a location through a symlink: after
//! `ln -s ~/.ssh ./s`, `cat ./s/id_rsa` reads the private key while its literal
//! path is inside the project. The core cannot look at the filesystem, so the
//! caller resolves each normalised path and the engine checks the literal and
//! the resolved path; the strictest verdict wins (ADR-009). The same caller
//! lists directories, so a glob operand is checked as the files it names
//! (`crate::expand`).

use std::collections::BTreeMap;

use crate::paths;
use crate::programs::NoResolver;

/// Resolves symlinks in normalised, slash-separated absolute paths.
pub trait PathResolver {
    /// The path `path` really refers to, or `None` when it is the same path or
    /// cannot be resolved. Paths that do not exist yet resolve through their
    /// deepest existing ancestor, so a new file written into a symlinked
    /// directory still resolves to where it would land.
    fn resolve(&self, path: &str) -> Option<String>;

    /// The names in the directory `dir` (a normalised absolute path), without
    /// `.` and `..`; empty when it is not a directory or cannot be read. Used
    /// only to expand an unquoted glob operand as the shell would
    /// (`crate::expand`). Without a filesystem nothing is listed, and the
    /// operand stays literal, as a glob that matches nothing does in `bash`.
    fn read_dir(&self, _dir: &str) -> Vec<String> {
        Vec::new()
    }
}

impl PathResolver for NoResolver {
    fn resolve(&self, _path: &str) -> Option<String> {
        None
    }
}

/// Where the OS lands for an absolute path that kept its `..` segments
/// ([`crate::paths::traversal`]): before each `..` the path so far is resolved,
/// so `..` steps up from the directory a symlink points to, not from the
/// link's name. `/p/c/../.ssh/id_rsa` with `c` → `/h/.config` is
/// `/h/.ssh/id_rsa`. Without a filesystem it is the lexical collapse.
#[must_use]
pub fn physical(path: &str, resolver: &dyn PathResolver) -> String {
    let (root, rest) = paths::split_root(path);
    let mut here = root.clone();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(real) = resolver.resolve(&here) {
                    here = paths::collapse(&real);
                }
                here = parent(&here, &root);
            }
            name => {
                if !here.ends_with('/') {
                    here.push('/');
                }
                here.push_str(name);
            }
        }
    }
    here
}

/// `path` without its last segment, never above `root`.
fn parent(path: &str, root: &str) -> String {
    match path.rfind('/') {
        Some(cut) if cut >= root.len() => path[..cut].to_owned(),
        _ => root.to_owned(),
    }
}

/// In-memory resolver for tests and conformance fixtures: symlink path →
/// target, and the files that exist. The longest link that is the path itself
/// or one of its ancestors is replaced by its target.
#[derive(Debug, Default, Clone)]
pub struct MapPathResolver {
    /// Symlink path → target.
    pub links: BTreeMap<String, String>,
    /// Absolute paths of existing files; they and their ancestor directories
    /// are what [`PathResolver::read_dir`] lists.
    pub files: Vec<String>,
}

impl PathResolver for MapPathResolver {
    /// Lists `dir` where its links lead.
    fn read_dir(&self, dir: &str) -> Vec<String> {
        let real = self.resolve(dir).unwrap_or_else(|| dir.to_owned());
        let prefix = format!("{}/", real.trim_end_matches('/'));
        let mut names: Vec<String> = self
            .files
            .iter()
            .filter_map(|f| f.strip_prefix(&prefix)?.split('/').next())
            .map(str::to_owned)
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn resolve(&self, path: &str) -> Option<String> {
        self.links
            .iter()
            .filter_map(|(link, target)| {
                let rest = path.strip_prefix(link.as_str())?;
                (rest.is_empty() || rest.starts_with('/')).then_some((link.len(), target, rest))
            })
            .max_by_key(|(len, _, _)| *len)
            .map(|(_, target, rest)| format!("{target}{rest}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_resolver_replaces_the_longest_linked_ancestor() {
        let r = MapPathResolver {
            links: BTreeMap::from([
                ("/p/s".to_owned(), "/h/.ssh".to_owned()),
                ("/p/s/k".to_owned(), "/h/.aws/credentials".to_owned()),
            ]),
            ..MapPathResolver::default()
        };
        assert_eq!(r.resolve("/p/s").as_deref(), Some("/h/.ssh"));
        assert_eq!(r.resolve("/p/s/id_rsa").as_deref(), Some("/h/.ssh/id_rsa"));
        assert_eq!(r.resolve("/p/s/k").as_deref(), Some("/h/.aws/credentials"));
        assert_eq!(r.resolve("/p/sx/id_rsa"), None);
        assert_eq!(r.resolve("/p/src/main.rs"), None);
        assert_eq!(NoResolver.resolve("/p/s"), None);
    }

    #[test]
    fn physical_steps_up_from_where_a_link_points() {
        let r = MapPathResolver {
            links: BTreeMap::from([("/p/c".to_owned(), "/h/.config".to_owned())]),
            ..MapPathResolver::default()
        };
        assert_eq!(physical("/p/c/../.ssh/id_rsa", &r), "/h/.ssh/id_rsa");
        assert_eq!(physical("/p/src/../README.md", &r), "/p/README.md");
        assert_eq!(physical("/p/c/./x/../y", &r), "/h/.config/y");
        assert_eq!(physical("/p/../../..", &r), "/");
        assert_eq!(physical("C:/a/../b", &NoResolver), "C:/b");
        // without a filesystem it is the lexical collapse
        assert_eq!(
            physical("/p/c/../.ssh/id_rsa", &NoResolver),
            "/p/.ssh/id_rsa"
        );
    }
}
