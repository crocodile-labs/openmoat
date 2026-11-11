//! What a restore changes, and changing it (ADR-085 §4).
//!
//! The plan compares the snapshot taken of the files as they are now (the
//! undo snapshot) with the one to restore. A file the snapshot to restore
//! left out (a secret, a large file) is never deleted or written, nor is one
//! that was there and ignored when it was taken (the agent may have changed
//! the ignore rules since: the snapshot does not cover it); a file the
//! undo snapshot could not keep is named, since no snapshot holds what it
//! held before the restore writes over it.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Serialize;

use super::lock::Held;
use super::paths::{self, Blocked, Content};
use super::{Listed, Store};

/// What a restore does to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// Its contents go back to the snapshot's.
    Changed,
    /// It is missing now and comes back.
    Added,
    /// The snapshot did not have it, so it is deleted.
    Deleted,
}

/// One path a restore changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    /// git's mode of what is written (`100644`, `100755`, `120000`); none for a delete.
    #[serde(skip)]
    mode: String,
    #[serde(skip)]
    blob: String,
    /// Why the undo snapshot does not hold what is at this path now, when it
    /// does not: the restore writes over it with no copy kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_copy: Option<String>,
}

/// What a restore of one snapshot changes.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub target: Listed,
    pub undo: Listed,
    pub changes: Vec<Change>,
    /// Paths the restore leaves as they are: those the snapshot left out, and
    /// every path not in it when its list of left-out paths was cut.
    pub kept: Vec<String>,
    /// Paths the restore leaves as they are because they were there and
    /// ignored when the snapshot was taken (the project ignores them no more):
    /// the snapshot does not cover them, so it cannot say they should go.
    pub not_covered: Vec<String>,
}

/// What a restore did.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Applied {
    pub written: usize,
    pub deleted: usize,
    /// Each path not changed, and why.
    pub skipped: Vec<(String, String)>,
}

impl Store {
    /// What restoring `target` over the state `undo` holds changes, limited
    /// to `only` (project-relative paths or folders) when given.
    pub fn plan(&self, target: Listed, undo: Listed, only: &[String]) -> Result<Plan> {
        let mut args = vec![
            "diff-tree".to_owned(),
            "-r".to_owned(),
            "-z".to_owned(),
            "--no-renames".to_owned(),
            "--raw".to_owned(),
            undo.tree.clone(),
            target.tree.clone(),
        ];
        if !only.is_empty() {
            args.push("--".to_owned());
            args.extend(only.iter().map(|p| format!(":(literal){p}")));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let raw = self.git.output(&args, None)?;
        let left_out: BTreeMap<&str, &str> = target
            .meta
            .left_out
            .iter()
            .map(|o| (o.path.as_str(), o.why.words()))
            .collect();
        let undo_left_out: BTreeMap<&str, &str> = undo
            .meta
            .left_out
            .iter()
            .map(|o| (o.path.as_str(), o.why.words()))
            .collect();
        let all_listed = target.meta.lists_all_left_out();
        let mut changes = Vec::new();
        let mut kept = Vec::new();
        let mut not_covered = Vec::new();
        for entry in parse_raw(&raw)? {
            if entry.status == 'D' {
                if left_out.contains_key(entry.path.as_str()) || !all_listed {
                    kept.push(entry.path);
                    continue;
                }
                if target.meta.may_have_ignored(&entry.path) {
                    not_covered.push(entry.path);
                    continue;
                }
                changes.push(Change {
                    path: entry.path,
                    kind: ChangeKind::Deleted,
                    mode: String::new(),
                    blob: String::new(),
                    no_copy: None,
                });
                continue;
            }
            let on_disk = std::fs::symlink_metadata(self.project.join(&entry.path)).is_ok();
            let (kind, no_copy) = if entry.status == 'A' {
                let why = on_disk.then(|| {
                    undo_left_out
                        .get(entry.path.as_str())
                        .map_or("the project's ignore rules leave it out", |w| *w)
                        .to_owned()
                });
                let kind = if on_disk {
                    ChangeKind::Changed
                } else {
                    ChangeKind::Added
                };
                (kind, why)
            } else {
                (ChangeKind::Changed, None)
            };
            changes.push(Change {
                path: entry.path,
                kind,
                mode: entry.new_mode,
                blob: entry.new_blob,
                no_copy,
            });
        }
        Ok(Plan {
            target,
            undo,
            changes,
            kept,
            not_covered,
        })
    }

    /// The differences of the first `max` paths `plan` changes, as a patch from
    /// the files now to the snapshot's (no external diff or text conversion runs).
    pub fn patch(&self, plan: &Plan, max: usize) -> Result<String> {
        if plan.changes.is_empty() {
            return Ok(String::new());
        }
        let mut args = vec![
            "diff-tree".to_owned(),
            "-r".to_owned(),
            "-p".to_owned(),
            "--no-renames".to_owned(),
            "--no-ext-diff".to_owned(),
            "--no-textconv".to_owned(),
            plan.undo.tree.clone(),
            plan.target.tree.clone(),
            "--".to_owned(),
        ];
        args.extend(
            plan.changes
                .iter()
                .take(max)
                .map(|c| format!(":(literal){}", c.path)),
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(String::from_utf8_lossy(&self.git.output(&args, None)?).into_owned())
    }

    /// Make the project match `plan`, under the store's lock (held since the
    /// undo snapshot, so no prune drops the snapshot between plan and write):
    /// deletes first, then writes, each path only through real folders inside
    /// the project.
    pub fn apply(&self, held: &Held, plan: &Plan) -> Result<Applied> {
        self.check_held(held)?;
        let mut applied = Applied::default();
        let (deletes, writes): (Vec<&Change>, Vec<&Change>) = plan
            .changes
            .iter()
            .partition(|c| c.kind == ChangeKind::Deleted);
        for change in deletes {
            match paths::checked_target(&self.project, &change.path, false) {
                Ok(path) => match paths::remove(&path) {
                    Ok(()) => applied.deleted += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => applied
                        .skipped
                        .push((change.path.clone(), error.to_string())),
                },
                Err(blocked) => applied.skipped.push((change.path.clone(), blocked.words())),
            }
        }
        for change in writes {
            match self.write(change) {
                Ok(()) => applied.written += 1,
                Err(why) => applied.skipped.push((change.path.clone(), why)),
            }
        }
        Ok(applied)
    }

    fn write(&self, change: &Change) -> Result<(), String> {
        let content = match change.mode.as_str() {
            "100644" | "100755" | "120000" => self
                .git
                .output(&["cat-file", "blob", &change.blob], None)
                .map_err(|e| format!("{e:#}"))?,
            "160000" => return Err("a nested repository is not restored".to_owned()),
            other => return Err(format!("git mode {other} is not restored")),
        };
        let path = paths::checked_target(&self.project, &change.path, true)
            .map_err(|b: Blocked| b.words())?;
        let made = if change.mode == "120000" {
            let target =
                String::from_utf8(content).map_err(|_| "the link's target is not UTF-8")?;
            paths::put(&path, &Content::Link { target: &target })
        } else {
            paths::put(
                &path,
                &Content::File {
                    bytes: &content,
                    executable: change.mode == "100755",
                },
            )
        };
        made.map_err(|e| e.to_string())
    }
}

/// One record of `diff-tree --raw -z`.
struct RawEntry {
    new_mode: String,
    new_blob: String,
    status: char,
    path: String,
}

/// `:old new old-id new-id S\0path\0`, record after record.
fn parse_raw(raw: &[u8]) -> Result<Vec<RawEntry>> {
    let text = String::from_utf8_lossy(raw);
    let mut fields = text.split('\0');
    let mut entries = Vec::new();
    while let Some(head) = fields.next() {
        if head.is_empty() {
            break;
        }
        let Some(path) = fields.next() else {
            bail!("git's list of differences ends early");
        };
        let parts: Vec<&str> = head.trim_start_matches(':').split(' ').collect();
        let [_, new_mode, _, new_blob, status] = parts[..] else {
            bail!("git's list of differences has a record it cannot read");
        };
        let status = status.chars().next().unwrap_or('?');
        if !matches!(status, 'A' | 'D' | 'M' | 'T') {
            bail!("git's list of differences has status {status}");
        }
        entries.push(RawEntry {
            new_mode: new_mode.to_owned(),
            new_blob: new_blob.to_owned(),
            status,
            path: path.to_owned(),
        });
    }
    Ok(entries)
}

#[cfg(test)]
pub(super) fn parse_raw_for_tests(raw: &[u8]) -> Vec<(char, String, String)> {
    parse_raw(raw)
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.status, e.new_mode, e.path))
        .collect()
}
