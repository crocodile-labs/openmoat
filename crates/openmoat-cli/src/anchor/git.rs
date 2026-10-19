//! Anchors as commits on [`REF`] in a git repository the person names.
//!
//! Plumbing only, on that repository only: the anchor file is read from the
//! ref's tree, the new tree is built with `hash-object` and `mktree`, the commit
//! with `commit-tree`, and the ref moved with `update-ref` against the commit it
//! was read at, so two anchors made at once cannot drop one another. The
//! working tree, the index, `HEAD` and the branches are never touched, and
//! nothing is pushed or fetched. The commit message carries a
//! `Signed-off-by` trailer with git's committer identity.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use super::Record;

/// The ref anchors are committed on.
pub const REF: &str = "refs/moat/anchors";

/// The file in the ref's tree that holds every anchor, one per line.
const FILE: &str = "anchors.jsonl";

/// git in one repository.
pub struct Repo {
    program: PathBuf,
    dir: PathBuf,
}

impl Repo {
    /// git at `program` in the repository at `dir`; an error when `dir` is not one.
    pub fn new(program: &Path, dir: &Path) -> Result<Self> {
        let repo = Self {
            program: program.to_path_buf(),
            dir: dir.to_path_buf(),
        };
        if repo.run(&["rev-parse", "--git-dir"], None).is_err() {
            bail!("{} is not a git repository", dir.display());
        }
        Ok(repo)
    }

    /// Run `git <args>` with `stdin`; its output on success, else an error with
    /// what git said.
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
        let mut child = Command::new(&self.program)
            .arg("-C")
            .arg(&self.dir)
            .args(["--no-pager", "-c", "core.fsmonitor=false"])
            .args(args)
            // The repository named on the command line, never one the
            // environment points at.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("running {}", self.program.display()))?;
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(bytes).context("writing to git")?;
        }
        let out = child.wait_with_output().context("waiting for git")?;
        if !out.status.success() {
            bail!(
                "git {} failed: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_owned())
    }

    /// The commit [`REF`] points at, if it exists.
    fn tip(&self) -> Option<String> {
        let target = format!("{REF}^{{commit}}");
        self.run(&["rev-parse", "--verify", "--quiet", &target], None)
            .ok()
            .filter(|tip| !tip.is_empty())
    }

    /// The anchor file at `tip`, empty when there is none yet.
    fn file_at(&self, tip: Option<&str>) -> Result<String> {
        match tip {
            None => Ok(String::new()),
            Some(tip) => self
                .run(&["cat-file", "blob", &format!("{tip}:{FILE}")], None)
                .map(|text| text + "\n"),
        }
    }

    /// Every anchor line on [`REF`]; an error when the ref does not exist.
    pub fn read(&self) -> Result<String> {
        let tip = self.tip().with_context(|| {
            format!("no anchors in {}: {REF} does not exist", self.dir.display())
        })?;
        self.file_at(Some(&tip))
    }

    /// Commit `record` on [`REF`]; the new commit's id.
    pub fn append(&self, record: &Record) -> Result<String> {
        let tip = self.tip();
        let mut text = self.file_at(tip.as_deref())?;
        text.push_str(&record.line()?);
        text.push('\n');
        let blob = self.run(&["hash-object", "-w", "--stdin"], Some(text.as_bytes()))?;
        let entry = format!("100644 blob {blob}\t{FILE}\n");
        let tree = self.run(&["mktree"], Some(entry.as_bytes()))?;
        let message = self.message(record)?;
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(parent) = &tip {
            args.extend(["-p", parent.as_str()]);
        }
        let commit = self.run(&args, Some(message.as_bytes()))?;
        // The old value guards against a concurrent anchor; none means the ref
        // must not exist yet.
        let zero = "0".repeat(blob.len());
        let old = tip.as_deref().unwrap_or(&zero);
        self.run(
            &["update-ref", "-m", "moat audit anchor", REF, &commit, old],
            None,
        )?;
        Ok(commit)
    }

    /// The commit message: what is anchored, signed off by git's committer.
    fn message(&self, record: &Record) -> Result<String> {
        let ident = self
            .run(&["var", "GIT_COMMITTER_IDENT"], None)
            .context("git has no committer identity; set user.name and user.email")?;
        let signer = ident
            .rfind('>')
            .map_or(ident.as_str(), |end| &ident[..=end])
            .to_owned();
        Ok(format!(
            "moat audit anchor: event {}\n\nevent {}\nhash {}\nevent time {}\nanchored {}\n\n\
             Signed-off-by: {signer}\n",
            record.event,
            record.event,
            record.hash,
            crate::time::timestamp(record.event_ms),
            crate::time::timestamp(record.anchored_ms),
        ))
    }
}
