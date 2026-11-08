//! Directory grants: `openmoat allow --dir` (ADR-007, amendment of 2026-11-07).
//!
//! A grant keeps only what the person chose: a directory, to read and write.
//! What it leaves out is worked out from the policy each time the policy is
//! loaded ([`DirGrant::rule`]): every path a `review` rule of the policy holds
//! writes to, found in the directory. So a protection a later policy adds also
//! holds in a grant made before it, and allowing a directory never answers a
//! review the policy holds for a file in it. Deny rules need nothing here: no
//! allow overrides one (invariant 1).
//!
//! Earlier releases wrote a plain allow rule with the exclusions of their day
//! copied in; [`DirGrant::from_rule`] recognises one, so `openmoat policy
//! upgrade` can turn it into a grant.

use anyhow::Result;
use openmoat_core::{Kind, Policy, RuleGroup, lint::covers};
use serde::{Deserialize, Serialize};

use crate::context::{absolute, path_string};
use crate::home::Home;

/// The placeholder for the project a rule is evaluated in.
const PROJECT: &str = "${project}";
/// How the rules earlier releases wrote for `--dir` begin their reason.
const OLD_REASONS: [&str; 2] = [
    "approved with `moat allow --dir` on ",
    "approved with `openmoat allow --dir` on ",
];
/// Characters a glob reads as more than themselves.
const GLOB_CHARS: [char; 7] = ['*', '?', '[', ']', '{', '}', '\\'];

/// A directory a person allowed with `openmoat allow --dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirGrant {
    /// `approved-<n>`, as decisions and `openmoat allow --remove` name it.
    pub id: String,
    /// When and how it was approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The directory as written and, when that differs, with its symlinks
    /// resolved: the hook checks a path both ways.
    pub dir: Vec<String>,
    /// Paths an earlier release's rule left out of the writes that the policy
    /// no longer holds for review, kept so the grant it became never allows
    /// more than that rule did. A new grant has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}

impl DirGrant {
    /// The allow rule this grant is under `policy`: reading and writing each
    /// spelling of the directory and everything below it, except writing what
    /// [`exclusions`] finds there and [`Self::except`].
    #[must_use]
    pub fn rule(&self, policy: &Policy, places: &Places) -> RuleGroup {
        let tree = tree(&self.dir);
        let left_out = exclusions(policy, &self.dir, places)
            .into_iter()
            .chain(self.except.iter().cloned())
            .map(|p| format!("!{p}"));
        RuleGroup {
            id: self.id.clone(),
            reason: self.reason.clone(),
            fs_read: tree.clone(),
            fs_write: tree.into_iter().chain(left_out).collect(),
            ..RuleGroup::default()
        }
    }

    /// The grant an earlier release's `--dir` rule stands for ([`is_old_rule`]),
    /// with [`Self::except`] holding what it left out that `policy` no longer
    /// does; `None` for any other rule.
    #[must_use]
    pub fn from_rule(rule: &RuleGroup, policy: &Policy, places: &Places) -> Option<Self> {
        let (dir, left_out) = old_shape(rule)?;
        let now = exclusions(policy, &dir, places);
        let except = left_out
            .into_iter()
            .filter(|old| !now.iter().any(|p| covers(Kind::FsWrite, p, old)))
            .map(str::to_owned)
            .collect();
        Some(Self {
            id: rule.id.clone(),
            reason: rule.reason.clone(),
            dir,
            except,
        })
    }
}

/// Whether `rule` is one an earlier release's `openmoat allow --dir` wrote:
/// its reason says so, it reads and writes each spelling of one directory and
/// everything below it, and its write exclusions all lie in the directory.
/// Every release before directory grants wrote that shape; only the exclusions
/// differ: none, then the `.git` paths (0.5.2), then also the `runs-later`
/// paths of the day.
#[must_use]
pub fn is_old_rule(rule: &RuleGroup) -> bool {
    old_shape(rule).is_some()
}

/// The directory spellings of an old `--dir` rule and what it left out of the
/// writes, without the `!`.
fn old_shape(rule: &RuleGroup) -> Option<(Vec<String>, Vec<&str>)> {
    let reason = rule.reason.as_deref()?;
    if !OLD_REASONS.iter().any(|old| reason.starts_with(old)) {
        return None;
    }
    let dir: Vec<String> = rule.fs_read.iter().step_by(2).cloned().collect();
    let tree = tree(&dir);
    // Nothing but the directory: no other kind, title or flag a person added.
    let bare = RuleGroup {
        id: rule.id.clone(),
        reason: rule.reason.clone(),
        fs_read: tree.clone(),
        fs_write: rule.fs_write.clone(),
        ..RuleGroup::default()
    };
    let plain = !dir.is_empty() && *rule == bare && dir.iter().all(|d| plain_dir(d));
    let left_out: Vec<&str> = rule
        .fs_write
        .strip_prefix(tree.as_slice())?
        .iter()
        .map(|p| p.strip_prefix('!'))
        .collect::<Option<_>>()?;
    let inside = left_out.iter().all(|p| dir.iter().any(|d| below(p, d)));
    (plain && inside).then_some((dir, left_out))
}

/// A directory a grant may name: not empty, no glob characters, which the
/// rule would read as wildcards, and no trailing `/`.
#[must_use]
pub fn plain_dir(dir: &str) -> bool {
    !dir.is_empty() && !dir.contains(GLOB_CHARS) && !dir.ends_with('/')
}

/// Each spelling of the directory and everything below it.
fn tree(dir: &[String]) -> Vec<String> {
    dir.iter()
        .flat_map(|d| [d.clone(), format!("{d}/**")])
        .collect()
}

/// Whether `pattern` names a path below `dir`.
fn below(pattern: &str, dir: &str) -> bool {
    pattern
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// The paths in the directory `dir` (each spelling) that a `review` rule of
/// `policy` holds writes to: its project paths (`${project}/.git/**`) and its
/// paths at any depth (`**/.vscode/**`) read as paths in the directory, and its
/// fixed paths (`~/.config/git/**`) where they can lie in it. A path another
/// one already covers is left out ([`covers`]), so the rule stays as short as
/// the policy allows.
#[must_use]
pub fn exclusions(policy: &Policy, dir: &[String], places: &Places) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let protected = policy
        .review
        .iter()
        .flat_map(|g| &g.fs_write)
        .filter(|p| !p.starts_with('!'));
    for pattern in protected {
        for spelling in dir {
            if let Some(found) = in_dir(pattern, spelling, places) {
                keep_broadest(&mut kept, found);
            }
        }
    }
    kept
}

/// `pattern` as it applies in `dir`, or `None` when it names nothing there.
fn in_dir(pattern: &str, dir: &str, places: &Places) -> Option<String> {
    if let Some(rest) = pattern.strip_prefix(PROJECT) {
        return (rest.is_empty() || rest.starts_with('/')).then(|| format!("{dir}{rest}"));
    }
    if let Some(rest) = pattern.strip_prefix("**/") {
        return Some(format!("{dir}/**/{rest}"));
    }
    // A form it cannot place (`~alice/…`) is kept: left out, it allows nothing.
    let lies_in = places
        .spellings(pattern)
        .is_none_or(|spelled| spelled.iter().any(|s| may_lie_in(s, dir)));
    lies_in.then(|| pattern.to_owned())
}

/// Add `found` unless a kept pattern covers it, dropping those it covers.
/// Of two that cover each other the first stays.
fn keep_broadest(kept: &mut Vec<String>, found: String) {
    if kept.iter().any(|p| covers(Kind::FsWrite, p, &found)) {
        return;
    }
    kept.retain(|p| !covers(Kind::FsWrite, &found, p));
    kept.push(found);
}

/// Whether a path the absolute pattern `spelled` matches can lie in `dir` or
/// be `dir`: the text before its first glob character is in `dir`, or is the
/// start of a path in it. Compared without case, which on a case-sensitive file
/// system only keeps a pattern more.
fn may_lie_in(spelled: &str, dir: &str) -> bool {
    let (spelled, dir) = (spelled.to_lowercase(), dir.to_lowercase());
    let stem = &spelled[..spelled.find(GLOB_CHARS).unwrap_or(spelled.len())];
    let inside = format!("{dir}/");
    stem == dir
        || stem.starts_with(&inside)
        || (stem.len() < spelled.len() && inside.starts_with(stem))
}

/// Where the policy's `~` and the agents' moved directories are on this
/// machine, to tell which of its fixed paths can lie in a granted directory.
#[derive(Debug, Clone, Default)]
pub struct Places {
    /// The home directory, as written and with its symlinks resolved.
    pub homes: Vec<String>,
    /// `(default, moved)` directories, as `EvalContext::moved_dirs` has them.
    pub moved: Vec<(String, String)>,
}

impl Places {
    /// The places of this machine and of the state directory `home`.
    pub fn here(home: &Home) -> Result<Self> {
        let written = absolute(&crate::home::user_home()?)?;
        let mut homes = vec![path_string(&written)];
        if let Ok(real) = std::fs::canonicalize(&written).map(|r| path_string(&r))
            && real != homes[0]
        {
            homes.push(real);
        }
        Ok(Self {
            homes,
            moved: crate::context::moved_dirs(home)?,
        })
    }

    /// Every absolute spelling of `pattern`: with `~` as each home, and with a
    /// moved directory in place of its default. `None` for a `~` form naming
    /// another user's home, which it cannot place.
    fn spellings(&self, pattern: &str) -> Option<Vec<String>> {
        let mut out: Vec<String> = self
            .moved
            .iter()
            .filter_map(|(default, dir)| {
                let rest = pattern.strip_prefix(default.as_str())?;
                (rest.is_empty() || rest.starts_with('/')).then(|| format!("{dir}{rest}"))
            })
            .collect();
        match pattern.strip_prefix('~') {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => {
                out.extend(self.homes.iter().map(|home| format!("{home}{rest}")));
            }
            Some(_) => return None,
            None => out.push(pattern.to_owned()),
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests;
