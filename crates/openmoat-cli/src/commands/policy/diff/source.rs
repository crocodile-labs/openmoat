//! Where the change and the policy come from: `git` for `--base`/`--head`,
//! or a unified diff on stdin.
//!
//! git runs read-only, through the push check's runner (`push/git.rs`): no
//! external diff, no text conversion, no file system monitor, no pager, no
//! prompt. With `--base`, every policy file is read as the base revision has
//! it, so the change under review cannot loosen the check that reviews it.

use std::io::{IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::{DEFAULT_POLICY, Policy, RepoPolicy};

use super::gate::{self, Finding};
use super::parse::{self, FileChange};
use crate::context;
use crate::push::git::{Git, Unchecked};

/// The repository policy's path in a repository (ADR-022).
pub const REPO_POLICY: &str = ".moat/policy.yaml";

/// At most this much of a diff is read. A larger change is still checked
/// path by path; its added lines are not searched, which is a finding.
const MAX_DIFF_BYTES: usize = 64 * 1024 * 1024;
/// At most this much of the list of changed files.
const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;
/// At most this much of a policy file (`context::parse_policy` has the same limit).
const MAX_POLICY_BYTES: usize = 1024 * 1024;
/// The time every git command of one check may take together.
const BUDGET: Duration = Duration::from_secs(300);

/// What one check reads.
pub struct Input {
    pub files: Vec<FileChange>,
    /// Why the diff was not read in full, when it was not.
    pub unchecked: Option<Finding>,
    pub policy: Policy,
    /// Repository paths of the policy files the check read.
    pub policy_files: Vec<String>,
    /// Where the policy came from, for the report.
    pub policy_source: String,
    pub repo_policy: Option<String>,
}

/// The unified diff on stdin, checked against `policy` (a file) or the default policy.
pub fn from_stdin(policy: Option<&Path>) -> Result<Input> {
    let mut stdin = std::io::stdin().lock();
    ensure!(
        !stdin.is_terminal(),
        "give --base (and --head), or pipe a unified diff on stdin"
    );
    let mut bytes = Vec::new();
    (&mut stdin)
        .take(MAX_DIFF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("reading the diff on stdin")?;
    ensure!(
        bytes.len() <= MAX_DIFF_BYTES,
        "the diff on stdin is larger than {} MiB, more than OpenMoat reads",
        MAX_DIFF_BYTES / (1024 * 1024)
    );
    let text = String::from_utf8_lossy(&bytes);
    let files = parse::parse(&text).context("reading the diff on stdin")?;
    let (user, source) = match policy {
        Some(path) => (context::load_policy(path)?, path.display().to_string()),
        None => default_policy()?,
    };
    let mut policy_files = vec![REPO_POLICY.to_owned()];
    policy_files.extend(policy.and_then(relative));
    Ok(Input {
        files,
        unchecked: None,
        policy: user,
        policy_files,
        policy_source: source,
        repo_policy: None,
    })
}

/// The change from the merge base of `base` and `head` to `head`, checked
/// against the policy as `base` has it.
pub fn from_git(base: &str, head: &str, policy: Option<&Path>) -> Result<Input> {
    let program = git_program()?;
    let deadline = (Instant::now() + BUDGET, BUDGET);
    let here = Git::new(&program, ".", deadline.0, deadline.1);
    let root = here
        .value(&["rev-parse", "--show-toplevel"])
        .map_err(failed)?
        .context("not inside a git repository")?;
    let git = Git::new(&program, &root, deadline.0, deadline.1);
    let base = commit(&git, base)?;
    let head = commit(&git, head)?;
    let fork = git
        .value(&["merge-base", &base, &head])
        .map_err(failed)?
        .with_context(|| {
            format!(
                "{base} and {head} have no common commit in this clone; fetch their history \
                 (`fetch-depth: 0` for actions/checkout)"
            )
        })?;
    let (files, unchecked) = changes(&git, &fork, &head)?;
    let (user, source, mut policy_files) = user_policy_at(&git, &base, policy)?;
    policy_files.push(REPO_POLICY.to_owned());
    let (policy, repo_policy) = match blob(&git, &base, REPO_POLICY)? {
        Some(text) => {
            let repo = RepoPolicy::parse(&text)
                .with_context(|| format!("invalid {REPO_POLICY} at {}", short(&base)))?;
            // Not trusted (`openmoat trust`): it only adds deny and review rules.
            let merged = repo.merge(&user, false)?;
            (merged, Some(format!("{REPO_POLICY} at {}", short(&base))))
        }
        None => (user, None),
    };
    Ok(Input {
        files,
        unchecked,
        policy,
        policy_files,
        policy_source: source,
        repo_policy,
    })
}

/// The policy `--policy` names (a repository file read at `base` when the
/// path is relative), else the default one; with where it came from and the
/// repository paths it was read from.
fn user_policy_at(
    git: &Git,
    base: &str,
    policy: Option<&Path>,
) -> Result<(Policy, String, Vec<String>)> {
    let Some(path) = policy else {
        let (user, source) = default_policy()?;
        return Ok((user, source, Vec::new()));
    };
    let Some(rel) = relative(path) else {
        let source = path.display().to_string();
        return Ok((context::load_policy(path)?, source, Vec::new()));
    };
    let text = blob(git, base, &rel)?
        .with_context(|| format!("{rel} does not exist at {}", short(base)))?;
    let user = context::parse_policy(text.into_bytes(), path)?;
    Ok((user, format!("{rel} at {}", short(base)), vec![rel]))
}

fn default_policy() -> Result<(Policy, String)> {
    let policy = Policy::parse(DEFAULT_POLICY).context("the default policy")?;
    Ok((policy, "the default policy".to_owned()))
}

/// `path` as a repository path, when it is relative: `/`-separated.
fn relative(path: &Path) -> Option<String> {
    let text = path.to_str()?.replace('\\', "/");
    (!path.is_absolute() && !text.starts_with('/'))
        .then(|| text.trim_start_matches("./").to_owned())
}

/// The first `git` on `PATH` in an absolute directory: a relative entry
/// would name a directory of the repository under review.
fn git_program() -> Result<PathBuf> {
    crate::environment::find_on_path("git").context("no git found on PATH")
}

fn failed(Unchecked(why): Unchecked) -> anyhow::Error {
    anyhow::Error::msg(why)
}

/// The commit `rev` names, as a full hash.
fn commit(git: &Git, rev: &str) -> Result<String> {
    if rev.is_empty() || rev.starts_with('-') {
        bail!("`{rev}` is not a revision");
    }
    let spec = format!("{rev}^{{commit}}");
    git.value(&["rev-parse", "--verify", "--quiet", &spec])
        .map_err(failed)?
        .with_context(|| format!("`{rev}` names no commit in this repository"))
}

fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

/// The files changed from `fork` to `head`: the patch for their added lines,
/// and git's own list of changed paths and modes, so a path the patch does
/// not name the way the parser reads it is still checked.
fn changes(git: &Git, fork: &str, head: &str) -> Result<(Vec<FileChange>, Option<Finding>)> {
    let options = [
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--ignore-submodules=none",
        "--submodule=short",
        "--full-index",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--no-relative",
    ];
    let mut args = vec!["diff"];
    args.extend(options);
    args.extend(["--raw", "-z", fork, head]);
    let raw = git.run(&args, MAX_LIST_BYTES).map_err(failed)?;
    ensure!(!raw.cut, "the change lists more files than OpenMoat reads");
    ensure!(raw.ok, "git could not list the changed files");
    let listed = raw_entries(&String::from_utf8_lossy(&raw.bytes));

    let mut args = vec!["diff"];
    args.extend(options);
    args.extend([fork, head]);
    let patch = git.run(&args, MAX_DIFF_BYTES).map_err(failed)?;
    let (mut files, unchecked) = if patch.cut {
        let why = format!(
            "the diff is larger than {} MiB, more than OpenMoat reads: its paths were checked, \
             its added lines were not searched for tokens",
            MAX_DIFF_BYTES / (1024 * 1024)
        );
        (Vec::new(), Some(gate::unchecked(why)))
    } else {
        ensure!(patch.ok, "git could not show the diff");
        let text = String::from_utf8_lossy(&patch.bytes);
        (parse::parse(&text).context("reading git's diff")?, None)
    };
    for entry in listed {
        let named = entry.new.as_deref().or(entry.old.as_deref());
        match files
            .iter_mut()
            .find(|f| f.paths().any(|p| Some(p) == named))
        {
            Some(file) => {
                file.old_mode = entry.old_mode.clone().or(file.old_mode.take());
                file.new_mode = entry.new_mode.clone().or(file.new_mode.take());
            }
            None => files.push(entry),
        }
    }
    Ok((files, unchecked))
}

/// `git diff --raw -z` records: `:<old mode> <new mode> <old> <new> <status>\0<path>\0`.
fn raw_entries(text: &str) -> Vec<FileChange> {
    let mut entries = Vec::new();
    let mut fields = text.split('\0');
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let mut meta = meta.trim_start_matches(':').split(' ');
        let mode = |m: Option<&str>| m.filter(|m| *m != "000000").map(str::to_owned);
        let (old_mode, new_mode) = (mode(meta.next()), mode(meta.next()));
        let status = meta.nth(2).unwrap_or_default();
        entries.push(FileChange {
            old: (!status.starts_with('A')).then(|| path.to_owned()),
            new: (!status.starts_with('D')).then(|| path.to_owned()),
            old_mode,
            new_mode,
            ..FileChange::default()
        });
    }
    entries
}

/// The text of `path` at `rev`; `None` when the revision has no such file.
/// Anything there but a regular file is an error, not a missing policy.
fn blob(git: &Git, rev: &str, path: &str) -> Result<Option<String>> {
    let listing = git
        .run(
            &["ls-tree", "-z", "--full-tree", rev, "--", path],
            MAX_LIST_BYTES,
        )
        .map_err(failed)?;
    ensure!(
        listing.ok && !listing.cut,
        "git could not list {path} at {}",
        short(rev)
    );
    let listing = String::from_utf8_lossy(&listing.bytes);
    let Some(entry) = listing.split('\0').find(|e| !e.is_empty()) else {
        return Ok(None);
    };
    let mode = entry.split(' ').next().unwrap_or_default();
    ensure!(
        matches!(mode, "100644" | "100755"),
        "{path} at {} is not a regular file (mode {mode})",
        short(rev)
    );
    let spec = format!("{rev}:{path}");
    let out = git
        .run(&["cat-file", "blob", &spec], MAX_POLICY_BYTES)
        .map_err(failed)?;
    ensure!(
        out.ok && !out.cut,
        "git could not read {path} at {} (at most {MAX_POLICY_BYTES} bytes)",
        short(rev)
    );
    String::from_utf8(out.bytes)
        .map(Some)
        .with_context(|| format!("{path} at {} is not UTF-8", short(rev)))
}
