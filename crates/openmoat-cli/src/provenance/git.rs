//! The commits, their changes and the provenance notes, read with git; and
//! the notes written (ADR-056).
//!
//! Reads go through the push check's read-only runner (`push/git.rs`: no
//! external diff, no text conversion, no file system monitor, no pager, no
//! prompt, one deadline). The one write, a note, goes through the anchor's
//! plumbing runner (`anchor/git.rs`): the note's blob with `hash-object`,
//! then `git notes --ref refs/notes/openmoat add -f -C <blob>`. Nothing is
//! pushed or fetched.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::attribution::{ChangedFile, added_lines};

use super::NOTES_REF;
use super::collect::CommitFacts;
use super::notes::MAX_NOTE_BYTES;
use crate::guard_relay::MAX_PAYLOAD_BYTES;
use crate::push::git::{Git, Unchecked};
use crate::taint::provenance::content_hash;

/// The most commits one run reads.
pub const MAX_COMMITS: usize = 1000;
/// At most this much of a commit's list of changes, or of its patch.
const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;
/// The time every git command of one run may take together.
const BUDGET: Duration = Duration::from_secs(300);
/// git's id of no object.
fn is_zero(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b == b'0')
}

/// git in one repository, for reading.
pub struct Reader {
    git: Git,
    program: PathBuf,
    /// The repository's top level, as git prints it.
    pub root: String,
}

impl Reader {
    /// The repository the current directory is in.
    pub fn here() -> Result<Self> {
        let program = git_program()?;
        let deadline = Instant::now() + BUDGET;
        let here = Git::new(&program, ".", deadline, BUDGET);
        let root = here
            .value(&["rev-parse", "--show-toplevel"])
            .map_err(failed)?
            .context("not inside a git repository")?;
        Ok(Self {
            git: Git::new(&program, &root, deadline, BUDGET),
            program,
            root,
        })
    }

    /// The commits `range` names, newest first: `A..B` as `git rev-list` reads
    /// it, one revision alone as that commit; by default the commits on `HEAD`
    /// that its upstream lacks, or `HEAD` alone without an upstream.
    pub fn commits(&self, range: Option<&str>) -> Result<Vec<String>> {
        let range = match range {
            Some(range) => range.to_owned(),
            None => match self.value(&["rev-parse", "--verify", "--quiet", "@{upstream}"])? {
                Some(_) => "@{upstream}..HEAD".to_owned(),
                None => "HEAD".to_owned(),
            },
        };
        if range.is_empty() || range.starts_with('-') {
            bail!("`{range}` is not a revision range");
        }
        if !range.contains("..") {
            return Ok(vec![self.commit(&range)?]);
        }
        let max = format!("--max-count={MAX_COMMITS}");
        let out = self
            .git
            .run(&["rev-list", &max, &range, "--"], MAX_LIST_BYTES)
            .map_err(failed)?;
        ensure!(
            out.ok && !out.cut,
            "git could not list the commits of `{range}`"
        );
        Ok(String::from_utf8_lossy(&out.bytes)
            .lines()
            .map(str::to_owned)
            .collect())
    }

    /// The commits from where `head` left `base` to `head`, as check-diff
    /// checks them.
    pub fn change(&self, base: &str, head: &str) -> Result<Vec<String>> {
        let base = self.commit(base)?;
        let head = self.commit(head)?;
        let fork = self
            .value(&["merge-base", &base, &head])?
            .context("the base and head have no common commit in this clone")?;
        self.commits(Some(&format!("{fork}..{head}")))
    }

    /// The full hash of the commit `rev` names.
    fn commit(&self, rev: &str) -> Result<String> {
        if rev.is_empty() || rev.starts_with('-') {
            bail!("`{rev}` is not a revision");
        }
        let spec = format!("{rev}^{{commit}}");
        self.value(&["rev-parse", "--verify", "--quiet", &spec])?
            .with_context(|| format!("`{rev}` names no commit in this repository"))
    }

    fn value(&self, args: &[&str]) -> Result<Option<String>> {
        self.git.value(args).map_err(failed)
    }

    /// What `commit` changes against its first parent, with content hashes.
    pub fn facts(&self, commit: &str) -> Result<CommitFacts> {
        let meta = self
            .value(&[
                "log",
                "-1",
                "--no-show-signature",
                "--format=%ct %P",
                commit,
            ])?
            .with_context(|| format!("git could not read commit {commit}"))?;
        let mut words = meta.split(' ');
        let commit_ms = seconds(words.next())?;
        let parent = words.next().filter(|p| !p.is_empty()).map(str::to_owned);
        let parent_ms = match &parent {
            Some(parent) => Some(seconds(
                self.value(&["log", "-1", "--no-show-signature", "--format=%ct", parent])?
                    .as_deref(),
            )?),
            None => None,
        };
        let mut base = vec![
            "diff-tree",
            "-r",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
        ];
        base.extend(["--no-commit-id", "--full-index", "--no-color"]);
        let tail: Vec<&str> = match &parent {
            Some(parent) => vec![parent.as_str(), commit],
            None => vec!["--root", commit],
        };
        let mut raw = base.clone();
        raw.extend(["--raw", "-z"]);
        raw.extend(&tail);
        let listed = self.git.run(&raw, MAX_LIST_BYTES).map_err(failed)?;
        ensure!(
            listed.ok && !listed.cut,
            "git could not list what {commit} changes"
        );
        let mut patch = base;
        patch.extend(["-p", "-U0", "--src-prefix=a/", "--dst-prefix=b/"]);
        patch.extend(&tail);
        let patch = self.git.run(&patch, MAX_LIST_BYTES).map_err(failed)?;
        // a patch too large to read claims no lines; the files still count
        let lines = if patch.ok && !patch.cut {
            added_lines(&String::from_utf8_lossy(&patch.bytes))
        } else {
            BTreeMap::new()
        };
        let mut files = Vec::new();
        for entry in raw_entries(&String::from_utf8_lossy(&listed.bytes)) {
            files.push(ChangedFile {
                added: lines.get(&entry.path).cloned().unwrap_or_default(),
                before: self.content(&entry.old_mode, &entry.old)?,
                after: self.content(&entry.new_mode, &entry.new)?,
                path: entry.path,
            });
        }
        Ok(CommitFacts {
            commit: commit.to_owned(),
            parent_ms,
            commit_ms,
            files,
        })
    }

    /// The content hash of blob `id` as the hook hashes files: `""` for no
    /// file, `None` for anything but a regular file within the hook's limit.
    fn content(&self, mode: &str, id: &str) -> Result<Option<String>> {
        if is_zero(id) || mode == "000000" {
            return Ok(Some(String::new()));
        }
        if !matches!(mode, "100644" | "100755") {
            return Ok(None);
        }
        let limit = usize::try_from(MAX_PAYLOAD_BYTES).unwrap_or(usize::MAX);
        let out = self
            .git
            .run(&["cat-file", "blob", id], limit)
            .map_err(failed)?;
        Ok((out.ok && !out.cut).then(|| content_hash(&out.bytes)))
    }

    /// Every commit that has a provenance note, with the note's blob.
    pub fn noted(&self) -> Result<BTreeMap<String, String>> {
        let refname = format!("--ref={NOTES_REF}");
        let exists = self.value(&["rev-parse", "--verify", "--quiet", NOTES_REF])?;
        if exists.is_none() {
            return Ok(BTreeMap::new());
        }
        let out = self
            .git
            .run(&["notes", &refname, "list"], MAX_LIST_BYTES)
            .map_err(failed)?;
        ensure!(
            out.ok && !out.cut,
            "git could not list the notes on {NOTES_REF}"
        );
        Ok(String::from_utf8_lossy(&out.bytes)
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(blob, commit)| (commit.to_owned(), blob.to_owned()))
            .collect())
    }

    /// The text of a note's blob.
    pub fn note_text(&self, blob: &str) -> Result<String> {
        let out = self
            .git
            .run(&["cat-file", "blob", blob], MAX_NOTE_BYTES)
            .map_err(failed)?;
        ensure!(out.ok && !out.cut, "git could not read note {blob}");
        Ok(String::from_utf8_lossy(&out.bytes).into_owned())
    }

    /// Store `text` as the note of `commit`, replacing any note it has.
    pub fn write_note(&self, commit: &str, text: &str) -> Result<()> {
        let repo = crate::anchor::git::Repo::new(&self.program, Path::new(&self.root))?;
        let blob = repo.run(&["hash-object", "-w", "--stdin"], Some(text.as_bytes()))?;
        repo.run(
            &[
                "notes", "--ref", NOTES_REF, "add", "-f", "-C", &blob, commit,
            ],
            None,
        )?;
        Ok(())
    }
}

/// One `git diff-tree --raw -z` record.
struct RawEntry {
    old_mode: String,
    new_mode: String,
    old: String,
    new: String,
    path: String,
}

/// `:<old mode> <new mode> <old> <new> <status>\0<path>\0` records.
fn raw_entries(text: &str) -> Vec<RawEntry> {
    let mut out = Vec::new();
    let mut fields = text.split('\0');
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let words: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        if let [old_mode, new_mode, old, new, ..] = words.as_slice() {
            out.push(RawEntry {
                old_mode: (*old_mode).to_owned(),
                new_mode: (*new_mode).to_owned(),
                old: (*old).to_owned(),
                new: (*new).to_owned(),
                path: path.to_owned(),
            });
        }
    }
    out
}

/// Committer seconds as milliseconds.
fn seconds(text: Option<&str>) -> Result<i64> {
    text.and_then(|t| t.trim().parse::<i64>().ok())
        .map(|s| s.saturating_mul(1000))
        .context("git printed no commit time")
}

/// The first `git` on `PATH` in an absolute directory: a relative entry
/// would name a directory of the repository being read.
fn git_program() -> Result<PathBuf> {
    crate::environment::find_on_path("git").context("no git found on PATH")
}

fn failed(Unchecked(why): Unchecked) -> anyhow::Error {
    anyhow::Error::msg(why)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_records_keep_modes_ids_and_paths() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let text = format!(
            ":000000 100644 {z} {a} A\0new file.rs\0:100644 000000 {a} {z} D\0gone\0:120000 120000 {a} {a} M\0link\0"
        );
        let entries = raw_entries(&text);
        let seen: Vec<(&str, &str, bool, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e.old_mode.as_str(),
                    e.new_mode.as_str(),
                    is_zero(&e.old),
                    e.path.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("000000", "100644", true, "new file.rs"),
                ("100644", "000000", false, "gone"),
                ("120000", "120000", false, "link"),
            ]
        );
        assert!(!is_zero(""));
    }

    #[test]
    fn commit_times_are_read_as_milliseconds() {
        assert_eq!(seconds(Some("1700000000")).unwrap(), 1_700_000_000_000);
        assert!(seconds(Some("x")).is_err());
        assert!(seconds(None).is_err());
    }
}
