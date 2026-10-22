//! Isolated tier on Linux: the bubblewrap mounts for one `moat run --isolate`
//! session (ADR-018).
//!
//! The agent gets a new root that holds only what the Lightweight tier's
//! Landlock rules grant ([`super::landlock`]): each read path bound read-only,
//! each write path read-write, the temp directory as an empty `tmpfs`. Unlike
//! Landlock, a mount can take something away inside a granted tree, so every
//! path the policy denies that exists when the session starts is covered:
//! - a denied read by an empty placeholder no one may open (mode `000`);
//! - a denied write by the path itself, bound read-only;
//! - a directory only the node of which is denied (`**/.claude`) by itself,
//!   bound read-write, so it cannot be renamed or removed.
//!
//! The project is walked for these (symlinks not followed); elsewhere only the
//! literal paths the deny rules name are looked up. A name a `**/` deny rule
//! names (`.env`, `.envrc`, `.moat`) that is missing directly in the project
//! gets an empty placeholder file there for the session, so it cannot be
//! created. A match created later anywhere else stays open, as listed.

use anyhow::{Result, bail};
use openmoat_core::ir::{Access, Checker, Effect, Enforcement};
use openmoat_core::{AtomicAction, Kind};

use super::landlock::{self, INSIDE_GRANTS_ALLOWANCE, Rules, TCP_PORT_ALLOWANCE};
use super::patterns::{
    AGENT_CONFIG, folders_above, has_glob, is_below, literal_tree, push_unique,
    runs_later_exclusion, split,
};
use super::{Grants, Report};

/// A name below a directory that only a rule for the whole subtree (`dir/**`)
/// matches: no policy names it.
const PROBE: &str = "__moat_probe__";

/// More entries than this in the project and the session is refused rather
/// than started with denied paths left uncovered.
const MAX_ENTRIES: usize = 1_000_000;

/// One mount of the agent's view, in the order bubblewrap applies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mount {
    /// The host path, read-only, at the same place.
    ReadOnly(String),
    /// The host path, read-write, at the same place.
    ReadWrite(String),
    /// An empty in-memory directory.
    Tmpfs(String),
    /// An empty placeholder no one may open, a directory when `dir`.
    Hide { path: String, dir: bool },
}

/// What `moat run --isolate` applies.
#[derive(Debug, Clone)]
pub struct Generated {
    /// The Landlock rules applied inside, on top of the mounts.
    pub rules: Rules,
    /// The agent's view.
    pub mounts: Vec<Mount>,
    /// Files created in the project for the session, so that a denied name
    /// cannot be created; removed afterwards while still empty.
    pub placeholders: Vec<String>,
    /// Losses and allowances of this backend.
    pub report: Report,
}

/// Generate the session's mounts for `ir` in `project` (its spellings, the
/// resolved one first).
pub fn generate(ir: &Enforcement, grants: &Grants, project: &[String]) -> Result<Generated> {
    let checker = ir.checker()?;
    let landlock::Generated { rules, mut report } = landlock::generate(ir, grants)?;
    let mut unenforced = Vec::new();
    for allowance in report
        .allowances
        .iter()
        .filter(|a| a.rule == INSIDE_GRANTS_ALLOWANCE)
    {
        for pattern in &allowance.patterns {
            push_unique(&mut unenforced, pattern.clone());
        }
    }
    // The network namespace reaches only the proxy; the mounts take over the rest.
    let replaced = [INSIDE_GRANTS_ALLOWANCE, TCP_PORT_ALLOWANCE];
    report
        .allowances
        .retain(|a| !replaced.contains(&a.rule.as_str()));
    if !unenforced.is_empty() {
        let patterns = unenforced;
        let message = "hidden, or read-only for writes, where they exist when the agent starts, \
                       and `.env`, `.envrc` and `.moat` directly in the project even when \
                       missing; a match created later stays open, and the hook still decides it";
        report.allowance(Kind::FsRead, "bwrap.created-later", patterns, message);
    }
    let mut trees = Vec::new();
    for path in rules.read.iter().filter(|p| !p.starts_with("/dev/")) {
        trees.push(Mount::ReadOnly(path.clone()));
    }
    for path in rules.write.iter().filter(|p| !p.starts_with("/dev/")) {
        trees.retain(|m| m != &Mount::ReadOnly(path.clone()));
        let tmp = grants.tmpdir.as_deref() == Some(path.as_str());
        trees.push(if tmp {
            Mount::Tmpfs(path.clone())
        } else {
            Mount::ReadWrite(path.clone())
        });
    }
    trees.sort_by_key(|m| depth(path_of(m)));
    let real = project.first().map(String::as_str);
    let mut masks = Masks {
        checker: &checker,
        project: real,
        mounts: Vec::new(),
        entries: 0,
    };
    if let Some(real) = real {
        masks.walk(real, false)?;
    }
    let mut placeholders = Vec::new();
    for name in denied_names(ir) {
        let Some(real) = real else { break };
        let path = format!("{real}/{name}");
        let missing = std::fs::symlink_metadata(&path).is_err();
        if missing && (masks.denied(Kind::FsRead, &path) || masks.denied_below(&path)) {
            placeholders.push(path.clone());
            masks.mounts.push(Mount::Hide { path, dir: false });
        }
    }
    masks.mounts.extend(literal_masks(ir, &trees, real));
    let mut mounts = trees;
    mounts.extend(respelled(&masks.mounts, project));
    Ok(Generated {
        rules,
        mounts,
        placeholders,
        report,
    })
}

/// The masks `moat run`'s network namespace adds over the whole root it binds
/// (`commands/run/linux/netns.rs`): each existing path a deny rule names
/// without a glob inside a read root or a `--write` path of `rules`, hidden or
/// made read-only as under `--isolate`. Landlock alone cannot deny inside those
/// grants, so `--write ~/.claude` would leave `~/.claude/settings.json`, and a
/// read root `~/.cargo` its `credentials.toml`, open to every command. The
/// project (`project`, its resolved spelling first) is left to the hook.
pub fn grant_masks(ir: &Enforcement, rules: &Rules, project: &[String]) -> Vec<Mount> {
    let trees = |paths: &[String], mount: fn(String) -> Mount| {
        paths
            .iter()
            .filter(|p| !p.starts_with("/dev/"))
            .map(|p| mount(p.clone()))
            .collect::<Vec<_>>()
    };
    let mut held = trees(&rules.read, Mount::ReadOnly);
    for tree in trees(&rules.write, Mount::ReadWrite) {
        held.retain(|m| path_of(m) != path_of(&tree));
        held.push(tree);
    }
    held.sort_by_key(|m| depth(path_of(m)));
    literal_masks(ir, &held, project.first().map(String::as_str))
}

/// The masks `moat run`'s network namespace adds in the project (`project`,
/// its resolved spelling first), for what exists directly in it:
/// - each agent configuration file or directory ([`AGENT_CONFIG`]), bound
///   read-only, so commands cannot write, remove or replace it;
/// - each file a `**/` write deny of `ir` names below a folder (an agent's hook
///   settings: `.claude/settings.json`, `.copilot/hooks`), read-only as under
///   `--isolate`;
/// - the folders above both (`.github`, `.pi`, `.claude`), each bound onto
///   itself, so it cannot be renamed away with the file inside and back.
///
/// One created later, or one in a subdirectory, stays writable; Landlock
/// grants the project whole.
pub fn project_masks(ir: &Enforcement, project: &[String]) -> Result<Vec<Mount>> {
    let Some(real) = project.first() else {
        return Ok(Vec::new());
    };
    let checker = ir.checker()?;
    let mut masks = Masks {
        checker: &checker,
        project: Some(real),
        mounts: Vec::new(),
        entries: 0,
    };
    for folder in agent_config_holders() {
        let path = format!("{real}/{folder}");
        if is_directory(&path) {
            push_mount(&mut masks.mounts, Mount::ReadWrite(path));
        }
    }
    for entry in AGENT_CONFIG {
        let rest = entry.strip_prefix("**/").unwrap_or(entry);
        let path = format!("{real}/{}", rest.strip_suffix("/**").unwrap_or(rest));
        if std::fs::symlink_metadata(&path).is_ok() {
            push_mount(&mut masks.mounts, Mount::ReadOnly(path));
        }
    }
    for rest in nested_write_denials(ir) {
        let mut paths = folders_above(&rest);
        paths.push(rest);
        for path in paths.iter().map(|p| format!("{real}/{p}")) {
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                masks.pin(&path, meta.is_dir());
            }
        }
    }
    let mut mounts = masks.mounts;
    mounts.sort_by_key(|m| depth(path_of(m)));
    Ok(respelled(&mounts, project))
}

/// The paths `**/` write denies of `ir` name below a folder, without a glob
/// (`.claude/settings.json`, `.copilot/hooks`); not a lone name such as
/// `.moat`, which in the project stays the hook's.
fn nested_write_denials(ir: &Enforcement) -> Vec<String> {
    let mut found = Vec::new();
    for pattern in ir.fs.write.deny.iter().flat_map(|r| split(&r.patterns).0) {
        let Some(rest) = pattern.strip_prefix("**/") else {
            continue;
        };
        let rest = rest.strip_suffix("/**").unwrap_or(rest);
        if rest.contains('/') && !has_glob(rest) {
            push_unique(&mut found, rest.to_owned());
        }
    }
    found
}

/// The folders above the agent configuration files, relative to where they
/// are found (`.github`, `.pi`).
fn agent_config_holders() -> impl Iterator<Item = String> {
    AGENT_CONFIG.iter().flat_map(|entry| folders_above(entry))
}

/// A directory, not a link to one.
fn is_directory(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Append `mount` unless the same path is already mounted.
fn push_mount(mounts: &mut Vec<Mount>, mount: Mount) {
    if !mounts.iter().any(|m| path_of(m) == path_of(&mount)) {
        mounts.push(mount);
    }
}

/// The masks for the absolute paths deny rules name without a glob that exist
/// inside `trees` (outermost first), outside the project `real`.
fn literal_masks(ir: &Enforcement, trees: &[Mount], real: Option<&str>) -> Vec<Mount> {
    let mut masks = Vec::new();
    for (path, kind, subtree) in denied_literals(ir) {
        let in_project = real.is_some_and(|p| path == p || is_below(&path, p));
        // The innermost tree holding it decides what is visible there.
        let holder = trees.iter().rev().find(|m| {
            let tree = path_of(m);
            path == tree || is_below(&path, tree)
        });
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let dir = meta.is_dir();
        // A deny rule names it, though a grant (`--write`) may cover it.
        let mask = match (holder, kind) {
            _ if in_project => None,
            (Some(Mount::ReadOnly(_) | Mount::ReadWrite(_)), Kind::FsRead) => {
                Some(Mount::Hide { path, dir })
            }
            (Some(Mount::ReadWrite(_)), _) if dir && !subtree => Some(Mount::ReadWrite(path)),
            (Some(Mount::ReadWrite(_)), _) => Some(Mount::ReadOnly(path)),
            // Not visible (a `tmpfs`, nothing), or read-only already.
            _ => None,
        };
        masks.extend(mask);
    }
    masks
}

/// The `bwrap` arguments for `mounts`, with `blank_file` and `blank_dir` as
/// the placeholders [`Mount::Hide`] binds.
pub fn args(mounts: &[Mount], blank_file: &str, blank_dir: &str) -> Vec<String> {
    let mut args = Vec::new();
    for mount in mounts {
        let (flag, from, to) = match mount {
            Mount::ReadOnly(p) => ("--ro-bind-try", p.as_str(), p.as_str()),
            Mount::ReadWrite(p) => ("--bind-try", p.as_str(), p.as_str()),
            Mount::Tmpfs(p) => {
                args.extend(["--tmpfs".to_owned(), p.clone()]);
                continue;
            }
            Mount::Hide { path, dir } => {
                let blank = if *dir { blank_dir } else { blank_file };
                ("--ro-bind", blank, path.as_str())
            }
        };
        args.extend([flag.to_owned(), from.to_owned(), to.to_owned()]);
    }
    args
}

fn path_of(mount: &Mount) -> &str {
    match mount {
        Mount::ReadOnly(p) | Mount::ReadWrite(p) | Mount::Tmpfs(p) => p,
        Mount::Hide { path, .. } => path,
    }
}

fn depth(path: &str) -> usize {
    path.split('/').filter(|c| !c.is_empty()).count()
}

/// The masks found under the resolved project, repeated under each of its
/// other spellings: each spelling is a mount of its own.
fn respelled(masks: &[Mount], project: &[String]) -> Vec<Mount> {
    let Some((real, others)) = project.split_first() else {
        return Vec::new();
    };
    let mut all = masks.to_vec();
    for other in others.iter().filter(|o| *o != real) {
        for mount in masks {
            let Some(rest) = path_of(mount).strip_prefix(real.as_str()) else {
                continue;
            };
            let path = format!("{other}{rest}");
            all.push(match mount {
                Mount::ReadOnly(_) => Mount::ReadOnly(path),
                Mount::ReadWrite(_) => Mount::ReadWrite(path),
                Mount::Tmpfs(_) => Mount::Tmpfs(path),
                Mount::Hide { dir, .. } => Mount::Hide { path, dir: *dir },
            });
        }
    }
    all
}

/// Names `**/<name>` and `**/<name>/**` deny rules give, without globs.
fn denied_names(ir: &Enforcement) -> Vec<String> {
    let mut names = Vec::new();
    for pattern in deny_patterns(ir) {
        let name = pattern
            .strip_prefix("**/")
            .map(|n| n.strip_suffix("/**").unwrap_or(n));
        if let Some(name) = name.filter(|n| !n.is_empty() && !n.contains('/') && !has_glob(n)) {
            push_unique(&mut names, name.to_owned());
        }
    }
    names
}

/// Absolute paths deny rules name without a glob, outermost first: the
/// access they deny (a read deny first) and whether the rule covers the
/// subtree (`dir/**`).
fn denied_literals(ir: &Enforcement) -> Vec<(String, Kind, bool)> {
    let mut found: Vec<(String, Kind, bool)> = Vec::new();
    for (access, kind) in [(&ir.fs.read, Kind::FsRead), (&ir.fs.write, Kind::FsWrite)] {
        for pattern in denials(access).filter(|p| p.starts_with('/')) {
            let Some(path) = literal_tree(pattern) else {
                continue;
            };
            if !found
                .iter()
                .any(|(p, k, _)| p == path && *k == Kind::FsRead)
            {
                found.retain(|(p, ..)| p != path);
                found.push((path.to_owned(), kind, pattern.ends_with("/**")));
            }
        }
    }
    found.sort_by_key(|(path, ..)| depth(path));
    found
}

/// Deny rules and allow exceptions of both file accesses.
fn deny_patterns(ir: &Enforcement) -> impl Iterator<Item = &str> {
    [&ir.fs.read, &ir.fs.write].into_iter().flat_map(denials)
}

/// The deny rules and allow exceptions of `access`, except the files run later
/// (`runs-later`), which the hook asks about: masking them would make them
/// unreadable and fail installs that write them.
fn denials(access: &Access) -> impl Iterator<Item = &str> {
    let denied = access.deny.iter().flat_map(|r| split(&r.patterns).0);
    let excepted = access.allow.iter().flat_map(|r| split(&r.patterns).1);
    denied.chain(excepted.filter(|p| !runs_later_exclusion(p)))
}

struct Masks<'a> {
    checker: &'a Checker,
    /// The project's resolved spelling, whose own agent folders are pinned.
    project: Option<&'a str>,
    mounts: Vec<Mount>,
    entries: usize,
}

impl Masks<'_> {
    fn denied(&self, kind: Kind, path: &str) -> bool {
        let atom = match kind {
            Kind::FsWrite => AtomicAction::FsWrite {
                path: path.to_owned(),
            },
            _ => AtomicAction::FsRead {
                path: path.to_owned(),
            },
        };
        self.checker.check_os(&atom) != Some(Effect::Allow)
    }

    /// Whether a rule for the subtree below `dir` denies writing there.
    fn denied_below(&self, dir: &str) -> bool {
        self.denied(Kind::FsWrite, &format!("{dir}/{PROBE}"))
    }

    /// Mask `path` as the policy says; whether to look below it.
    fn classify(&mut self, path: &str, dir: bool, read_only_above: bool) -> bool {
        let below = |kind| dir && self.denied(kind, &format!("{path}/{PROBE}"));
        if self.denied(Kind::FsRead, path) || below(Kind::FsRead) {
            self.mounts.push(Mount::Hide {
                path: path.to_owned(),
                dir,
            });
            return false;
        }
        if read_only_above {
            return dir;
        }
        self.pin(path, dir);
        // A folder holding an agent's configuration (`.github`, `.pi`) directly
        // in the project: renamed away and back, a file written inside it under
        // the other name would be loaded. Not deeper, where packages bring
        // their own `.github` into `node_modules`.
        let holder = dir
            && self
                .project
                .is_some_and(|root| agent_config_holders().any(|f| path == format!("{root}/{f}")));
        if holder {
            push_mount(&mut self.mounts, Mount::ReadWrite(path.to_owned()));
        }
        dir
    }

    /// Mask `path` as the write rules say: a directory below which writing is
    /// denied read-only, a denied file read-only and a denied directory node
    /// bound onto itself, so it cannot be renamed or removed.
    fn pin(&mut self, path: &str, dir: bool) {
        if dir && self.denied_below(path) {
            push_mount(&mut self.mounts, Mount::ReadOnly(path.to_owned()));
        } else if self.denied(Kind::FsWrite, path) {
            let pin = if dir {
                Mount::ReadWrite
            } else {
                Mount::ReadOnly
            };
            push_mount(&mut self.mounts, pin(path.to_owned()));
        }
    }

    /// Classify every entry below `dir`, symlinks not followed.
    fn walk(&mut self, dir: &str, read_only: bool) -> Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                bail!(
                    "the project has more than {MAX_ENTRIES} files and directories; `openmoat run \
                     --isolate` looks at each to hide what the policy denies"
                );
            }
            let is_dir = entry.file_type()?.is_dir();
            let Ok(name) = entry.file_name().into_string() else {
                bail!(
                    "{dir} holds a name that is not UTF-8, which `openmoat run --isolate` cannot mount over"
                );
            };
            let path = format!("{dir}/{name}");
            let read_only_here = read_only || (is_dir && self.denied_below(&path));
            if self.classify(&path, is_dir, read_only) {
                self.walk(&path, read_only_here)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
