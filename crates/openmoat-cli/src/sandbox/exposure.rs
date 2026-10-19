//! Whether a `moat run` session's Landlock grants reach OpenMoat's state
//! directory.
//!
//! Landlock only grants ([`super::landlock`]): `kernel-self` denies reading the
//! audit log, the policy lock and the other state files, but inside a granted
//! tree (the project, a read root such as `/tmp`, a `--write` path, the temp
//! directory) that deny cannot hold, and a write grant there would let
//! commands change them. So on Linux `moat run` refuses to start where a grant
//! holds the state directory or lies inside it.
//!
//! `moat run --isolate` mounts an empty `tmpfs` over the temp directory, so a
//! state directory below it is hidden there. Every other granted tree is bound
//! as it is: bubblewrap covers the state files that exist when the session
//! starts, but not the ones made later (the audit log's `-wal`) nor the
//! `audit.db*` glob outside the project, so `--isolate` refuses those too.

use std::path::Path;

use super::landlock::Rules;
use super::patterns::is_below;
use crate::context::path_string;

/// One granted tree as the agent sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The granted path, symlinks resolved.
    pub path: String,
    /// What is on the host shows there; false where an empty `tmpfs` covers it.
    pub shown: bool,
}

/// How a grant reaches the state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// The state directory is this granted tree or lies inside it.
    Inside(String),
    /// This granted path lies inside the state directory.
    Holds(String),
}

/// Whether `path` is `dir` or below it; trailing slashes do not count, and
/// `case_insensitive` compares as such a file system does.
pub fn within(path: &str, dir: &str, case_insensitive: bool) -> bool {
    let fold = |p: &str| {
        let p = trimmed(p);
        if case_insensitive {
            p.to_lowercase()
        } else {
            p.to_owned()
        }
    };
    let (path, dir) = (fold(path), fold(dir));
    path == dir || is_below(&path, &dir)
}

/// `path` without trailing slashes; the root stays `/`.
fn trimmed(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') {
        "/"
    } else {
        trimmed
    }
}

fn depth(path: &str) -> usize {
    path.split('/').filter(|c| !c.is_empty()).count()
}

/// The grant through which the agent would see into `state`, if any: one shown
/// inside it, or the innermost tree holding it when that one is shown (an
/// empty `tmpfs` wins over a tree bound at the same place).
pub fn exposing(state: &str, grants: &[Grant], case_insensitive: bool) -> Option<Exposure> {
    let inside_state = grants.iter().find(|g| {
        g.shown
            && within(&g.path, state, case_insensitive)
            && !within(state, &g.path, case_insensitive)
    });
    if let Some(grant) = inside_state {
        return Some(Exposure::Holds(grant.path.clone()));
    }
    let holder = grants
        .iter()
        .filter(|g| within(state, &g.path, case_insensitive))
        .max_by_key(|g| (depth(&g.path), !g.shown))?;
    holder.shown.then(|| Exposure::Inside(holder.path.clone()))
}

/// The paths `rules` grant, resolved; `empty` is the one an empty `tmpfs`
/// covers (`moat run --isolate`'s temp directory).
pub fn grants(rules: &Rules, empty: Option<&str>) -> Vec<Grant> {
    rules
        .read
        .iter()
        .chain(&rules.write)
        .map(|granted| {
            let path = resolved(Path::new(granted));
            let shown = empty != Some(path.as_str());
            Grant { path, shown }
        })
        .collect()
}

/// `path` with its symlinks resolved: those of its deepest existing ancestor
/// when it does not exist yet, and as it is when none resolves.
pub fn resolved(path: &Path) -> String {
    for ancestor in path.ancestors() {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            let rest = path.strip_prefix(ancestor).unwrap_or(Path::new(""));
            let real = if rest.as_os_str().is_empty() {
                real
            } else {
                real.join(rest)
            };
            return path_string(&real);
        }
    }
    path_string(path)
}

/// The state directory `state`, resolved, and how `rules` reach it.
pub fn find(state: &Path, rules: &Rules, empty: Option<&str>) -> Option<(String, Exposure)> {
    let state = resolved(state);
    let ci = crate::context::CASE_INSENSITIVE_PATHS;
    let exposure = exposing(&state, &grants(rules, empty), ci)?;
    Some((state, exposure))
}

/// Why `moat run` refuses to start: `rules` would show the state directory
/// `state` to the agent. `tmpdir` is the session's temp directory, which
/// `isolated` (`--isolate`) covers with an empty `tmpfs`.
pub fn refusal(
    state: &Path,
    rules: &Rules,
    tmpdir: Option<&str>,
    isolated: bool,
) -> Option<String> {
    let (state_dir, exposure) = find(state, rules, tmpdir.filter(|_| isolated))?;
    let isolate_hides = !isolated && find(state, rules, tmpdir).is_none();
    let fix = if isolate_hides {
        ", or use `moat run --isolate`, which hides it under an empty temp directory"
    } else {
        ""
    };
    let cause = "Landlock cannot keep the audit log and the policy lock from commands inside a \
                 granted directory";
    Some(match exposure {
        Exposure::Inside(root) => format!(
            "OpenMoat's state directory {state_dir} is inside {root}, which the sandbox grants; \
             {cause}, so `moat run` refuses to start. Move MOAT_HOME out of {root}{fix}"
        ),
        Exposure::Holds(path) => format!(
            "{path}, which the sandbox grants, is inside OpenMoat's state directory {state_dir}; \
             {cause}, so `moat run` refuses to start. Grant a path outside it, or move MOAT_HOME \
             elsewhere"
        ),
    })
}

// Its tests use Unix paths and symlinks.
#[cfg(all(test, unix))]
mod tests;
