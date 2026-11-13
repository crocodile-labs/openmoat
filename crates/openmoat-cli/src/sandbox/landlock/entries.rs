//! The Lightweight tier on Linux without a network namespace (ADR-090).
//!
//! A Landlock rule grants a directory with everything below it, created later
//! included, and nothing granted can be taken away again. Granting the project
//! whole would hand every command the project's `.env` files, its `.git` and
//! its `.moat`. Where no mount can cover them (no bubblewrap, or no user
//! namespace for it), the project is granted entry by entry instead:
//! - the project itself only for listing ([`super::Rules::list`]), so no entry
//!   can be created, renamed or removed directly in it: a missing `.env`,
//!   `.envrc` or `.moat` cannot appear, and none can be moved aside;
//! - each entry the policy lets commands read, read-only, or read-write when
//!   it lets them write it and everything below it; an entry whose reading
//!   the policy denies (`.env`) gets no rule at all;
//! - a folder that holds a path a rule names below it (`.claude` for
//!   `**/.claude/settings.json`, `.moat` for `**/.moat/policy.lock`, `.github`
//!   for `.github/hooks`) the same way, one level further down.
//!
//! A granted tree that holds the project (a read root such as `/tmp`) is
//! granted around it: each directory on the way down for listing, every other
//! entry as the tree was. Symbolic links get no rule of their own: a rule
//! follows a link, and what a link names is decided where it points.
//!
//! What stays open is what lies deeper in a granted entry (`sub/.env`):
//! [`open`] names it from the masks the Isolated tier would apply.

use anyhow::{Result, bail};
use openmoat_core::ir::{Checker, Effect, Enforcement};
use openmoat_core::{AtomicAction, Kind};

use super::Rules;
use crate::sandbox::Report;
use crate::sandbox::bwrap::{Mount, without_runs_later};
use crate::sandbox::patterns::{Spot, folders_above, has_glob, is_below, push_unique, split, spot};

/// The loss listed when the project is granted entry by entry.
pub const ENTRIES_LOSS: &str = "landlock.project-entries";

/// A name below a directory that only a rule for the whole subtree matches.
const PROBE: &str = "__moat_probe__";

/// More rules than this and the run is refused rather than started with a
/// grant that is not what the policy says.
const MAX_RULES: usize = 100_000;

/// Grant the project (`project`, its resolved spelling first) entry by entry
/// in `rules`, where it or a tree holding it is granted whole, and list the
/// loss in `report`. Nothing changes where the project is not granted.
pub fn split_project(
    ir: &Enforcement,
    rules: &mut Rules,
    report: &mut Report,
    project: &[String],
) -> Result<()> {
    let Some(real) = project.first() else {
        return Ok(());
    };
    // Landlock follows every link of a rule's path, so each grant is compared
    // where it resolves: a read root `~/go` linked to the project's parent
    // holds the project as surely as the parent itself does.
    let spelling = |p: &String| project.contains(p) || resolved(p) == *real;
    let writable = rules.write.iter().any(spelling);
    let granted = writable || rules.read.iter().any(spelling);
    let around = |list: &[String]| -> Vec<(String, String)> {
        list.iter()
            .map(|g| (g.clone(), resolved(g)))
            .filter(|(_, r)| is_below(real, r))
            .collect()
    };
    let (read_above, write_above) = (around(&rules.read), around(&rules.write));
    if !granted && read_above.is_empty() && write_above.is_empty() {
        return Ok(());
    }
    let ir = without_runs_later(ir);
    let checker = ir.checker()?;
    let above = |p: &String, list: &[(String, String)]| list.iter().any(|(g, _)| g == p);
    rules
        .read
        .retain(|p| !spelling(p) && !above(p, &read_above));
    rules
        .write
        .retain(|p| !spelling(p) && !above(p, &write_above));
    let mut split = Split {
        checker: &checker,
        holders: holders(&ir, project),
        real,
        rules,
        count: 0,
    };
    // Each from where it resolves, as Landlock would grant it.
    for (trees, writable) in [(&read_above, false), (&write_above, true)] {
        for (_, tree) in trees {
            split.around(tree, writable)?;
        }
    }
    // A tree above the project that grants writing granted it inside too.
    split.dir(real, writable || !write_above.is_empty())?;
    let message = "Landlock grants a folder with everything in it, so the project is granted \
                   entry by entry: commands cannot create, rename or remove entries directly in \
                   it or in the folders that hold an agent's settings, `.env` files there stay \
                   unreadable and `.git` and `.moat` read-only; create what a command needs \
                   there before the run, or install bubblewrap for a view that needs none of this";
    report.loss(Kind::FsWrite, ENTRIES_LOSS, message.to_owned());
    Ok(())
}

/// The folders, relative to the project, that hold a path a rule of `ir`
/// names below them (`.claude`, `.github`, `.github/copilot`, `.moat`).
fn holders(ir: &Enforcement, project: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let accesses = [&ir.fs.read, &ir.fs.write];
    for access in accesses {
        let denied = access.deny.iter().flat_map(|r| split(&r.patterns).0);
        let excepted = access.allow.iter().flat_map(|r| split(&r.patterns).1);
        for pattern in denied.chain(excepted) {
            let in_project = project
                .iter()
                .find_map(|p| pattern.strip_prefix(p.as_str())?.strip_prefix('/'));
            let rest = in_project.or(match spot(pattern) {
                Spot::Anywhere(rest) => Some(rest),
                Spot::Project(_) | Spot::Absolute(_) => None,
            });
            let Some(rest) = rest.map(|r| r.trim_start_matches("**/")) else {
                continue;
            };
            for folder in folders_above(rest) {
                if !has_glob(&folder) {
                    push_unique(&mut found, folder);
                }
            }
        }
    }
    found
}

struct Split<'a> {
    checker: &'a Checker,
    holders: Vec<String>,
    real: &'a str,
    rules: &'a mut Rules,
    count: usize,
}

impl Split<'_> {
    /// Whether the policy lets commands do `kind` at `path`.
    fn allowed(&self, kind: Kind, path: &str) -> bool {
        let atom = match kind {
            Kind::FsWrite => AtomicAction::FsWrite {
                path: path.to_owned(),
            },
            _ => AtomicAction::FsRead {
                path: path.to_owned(),
            },
        };
        self.checker.check_os(&atom) == Some(Effect::Allow)
    }

    /// Whether `kind` is allowed at `path` and, for a directory, everywhere below it.
    fn allowed_all(&self, kind: Kind, path: &str, dir: bool) -> bool {
        let below = || self.allowed(kind, &format!("{path}/{PROBE}"));
        self.allowed(kind, path) && (!dir || below())
    }

    fn rule(&mut self, list: fn(&mut Rules) -> &mut Vec<String>, path: String) -> Result<()> {
        self.count += 1;
        if self.count > MAX_RULES {
            bail!(
                "granting the project entry by entry would need more than {MAX_RULES} Landlock \
                 rules; install bubblewrap (`apt install bubblewrap`) so `openmoat run` can \
                 cover what the policy denies with mounts instead"
            );
        }
        push_unique(list(self.rules), path);
        Ok(())
    }

    /// Grant the project's directory `dir` entry by entry.
    fn dir(&mut self, dir: &str, writable: bool) -> Result<()> {
        self.rule(|r| &mut r.list, dir.to_owned())?;
        for (name, is_dir) in entries(dir)? {
            let path = join(dir, &name);
            if !self.allowed_all(Kind::FsRead, &path, is_dir) {
                continue;
            }
            let rest = &path[self.real.len() + 1..];
            if is_dir && self.holders.iter().any(|h| h == rest) {
                self.dir(&path, writable)?;
                continue;
            }
            self.rule(|r| &mut r.read, path.clone())?;
            if writable && self.allowed_all(Kind::FsWrite, &path, is_dir) {
                self.rule(|r| &mut r.write, path)?;
            }
        }
        Ok(())
    }

    /// Grant `tree`, which holds the project, around it: each directory on
    /// the way down for listing, every other entry as `tree` was granted.
    fn around(&mut self, tree: &str, writable: bool) -> Result<()> {
        let mut dir = tree.to_owned();
        while dir != self.real {
            let Some(rest) = self.real.strip_prefix(dir.trim_end_matches('/')) else {
                break;
            };
            let rest = rest.trim_start_matches('/');
            let next = join(&dir, rest.split('/').next().unwrap_or(rest));
            self.rule(|r| &mut r.list, dir.clone())?;
            for (name, _) in entries(&dir)? {
                let path = join(&dir, &name);
                if path == next {
                    continue;
                }
                self.rule(|r| &mut r.read, path.clone())?;
                if writable {
                    self.rule(|r| &mut r.write, path)?;
                }
            }
            dir = next;
        }
        Ok(())
    }
}

/// `path` with every link resolved, as a Landlock rule on it opens it; as
/// written when it cannot be resolved (it does not exist, and no rule on it
/// can be made either).
pub fn resolved(path: &str) -> String {
    std::fs::canonicalize(path).map_or_else(
        |_| path.to_owned(),
        |real| crate::context::path_string(&real),
    )
}

/// `name` in the directory `dir`, which may be `/`.
fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

/// The entries of `dir` with whether each is a directory, sorted; symbolic
/// links and names that are not UTF-8 left out (no rule for them is stricter).
fn entries(dir: &str) -> Result<Vec<(String, bool)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if let Ok(name) = entry.file_name().into_string() {
            found.push((name, kind.is_dir()));
        }
    }
    found.sort();
    Ok(found)
}

/// The paths of `masks`, which the Isolated tier would put over the project,
/// that `rules` still leave open: a hidden path some rule lets commands read,
/// a read-only one some rule lets them write, and a folder pinned against
/// renaming whose parent some rule lets them change. Each as `masks` names it.
pub fn open(masks: &[Mount], rules: &Rules) -> Vec<String> {
    // The masks are resolved paths, and a rule grants where it resolves.
    let resolve = |list: &[String]| list.iter().map(|g| resolved(g)).collect::<Vec<_>>();
    let (read, write) = (resolve(&rules.read), resolve(&rules.write));
    let covers = |list: &[String], path: &str| list.iter().any(|g| g == path || is_below(path, g));
    let readable = |p: &str| covers(&read, p) || covers(&write, p);
    let mut found = Vec::new();
    for mask in masks {
        let open = match mask {
            Mount::Hide { path, .. } => readable(path).then_some(path),
            Mount::ReadOnly(path) => covers(&write, path).then_some(path),
            Mount::ReadWrite(path) => {
                let parent = path.rsplit_once('/').map_or("/", |(p, _)| p);
                covers(&write, parent).then_some(path)
            }
            Mount::Tmpfs(_) => None,
        };
        if let Some(path) = open {
            push_unique(&mut found, path.clone());
        }
    }
    found
}

#[cfg(test)]
mod tests;
