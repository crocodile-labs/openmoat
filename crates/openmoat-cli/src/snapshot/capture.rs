//! Taking a snapshot: list the project's files as git sees them (its
//! `.gitignore` files and `.git/info/exclude` honoured), leave out what a
//! deny rule names and what is too large, and commit the rest to the store.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{AtomicAction, CompiledPolicy, EvalContext, Policy, Verdict};

use super::git::ShadowGit;
use super::lock::Held;
use super::paths::{in_state_folder, is_plain};
use super::{LeftOut, META_VERSION, Meta, Omitted, REF_PREFIX, Reason, Store};

/// At most this many left-out paths are listed in a snapshot; the count is always kept.
pub const MAX_LISTED: usize = 10_000;

/// How large a snapshot may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// A file larger than this is left out (and named).
    pub file_bytes: u64,
    /// More files than this and no snapshot is taken.
    pub files: usize,
    /// More bytes in all than this and no snapshot is taken.
    pub total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            file_bytes: 5 << 20,
            files: 100_000,
            total_bytes: 1 << 30,
        }
    }
}

/// What taking a snapshot did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// A new snapshot.
    New(super::Listed),
    /// The files are as the newest snapshot holds them; none was added.
    Unchanged(super::Listed),
}

impl Taken {
    pub fn snapshot(&self) -> &super::Listed {
        match self {
            Self::New(s) | Self::Unchanged(s) => s,
        }
    }
}

/// Which paths a deny rule of the policy names, for reading or for writing: a
/// secret is never copied into the store, and OpenMoat's and the agents' own
/// files are left to the person's own tools.
pub struct Denied {
    compiled: CompiledPolicy<'static>,
    /// The project as the policy's paths spell it.
    root: String,
}

impl Denied {
    pub fn new(policy: Policy, ctx: &EvalContext) -> Result<Self> {
        let root = ctx.project.clone().context("a snapshot needs a project")?;
        Ok(Self {
            compiled: CompiledPolicy::compile_owned(policy, ctx)?,
            root,
        })
    }

    pub fn names(&self, rel: &str) -> bool {
        let path = format!("{}/{rel}", self.root.trim_end_matches('/'));
        [
            AtomicAction::FsRead { path: path.clone() },
            AtomicAction::FsWrite { path },
        ]
        .iter()
        .any(|atom| {
            self.compiled
                .evaluate_atomic(atom)
                .is_some_and(|d| d.verdict == Verdict::Deny)
        })
    }
}

impl Store {
    /// Take a snapshot of the project now, under the store's lock.
    pub fn take(
        &self,
        held: &Held,
        denied: &Denied,
        limits: Limits,
        reason: Reason,
        session: Option<&str>,
    ) -> Result<Taken> {
        self.check_held(held)?;
        let shared = self.git.index().to_path_buf();
        if self.git.pin_attributes()? {
            // Its entries may hold blobs the project's attributes converted.
            remove_if_there(&shared).context("starting the snapshot index again")?;
        }
        // This process's own copy of the index, which keeps what git already
        // hashed: no `index.lock` is shared with another process, and the
        // shared index changes only by a rename once the tree is written.
        let own = private_name(&shared);
        match fs::copy(&shared, &own) {
            // The copy keeps the shared index's modification time: git trusts
            // a cached entry only for a file older than its index ("racy git"),
            // and a copy stamped now would make a file changed in the same
            // second, at the same size, look unchanged, so the snapshot would
            // keep its old bytes.
            Ok(_) => keep_mtime(&shared, &own).context("copying the snapshot index's time")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("copying the snapshot index"),
        }
        let git = self.git.with_index(own.clone());
        let tree = (|| {
            let (kept, omitted, bytes) = self.select(denied, limits)?;
            stage(&git, &kept)?;
            let tree = git.text(&["write-tree"], None)?;
            fs::rename(&own, &shared).context("keeping the snapshot index")?;
            Ok::<_, anyhow::Error>((tree, kept.len(), omitted, bytes))
        })();
        let _ = remove_if_there(&own);
        let (tree, files, mut omitted, bytes) = tree?;
        let left_out_total = omitted.len();
        omitted.truncate(MAX_LISTED);
        let mut ignored = self.ignored_paths()?;
        let ignored_total = ignored.len();
        ignored.truncate(MAX_LISTED);
        let meta = Meta {
            version: META_VERSION,
            reason,
            session: session.map(str::to_owned),
            files,
            bytes,
            left_out: omitted,
            left_out_total,
            ignored,
            ignored_total,
        };
        // Unchanged files add no snapshot, except a run's start: a plain
        // `openmoat restore` goes back to the newest one, so each run records
        // its own, a commit of the same tree (no file is stored twice).
        let newest = self.list()?.pop();
        if let Some(newest) = &newest
            && newest.tree == tree
            && newest.meta.left_out == meta.left_out
            && newest.meta.ignored == meta.ignored
            && (reason != Reason::RunStart
                || (newest.meta.reason == reason && newest.meta.session == meta.session))
        {
            return Ok(Taken::Unchanged(newest.clone()));
        }
        let message = serde_json::to_string(&meta)?;
        let commit = self
            .git
            .text(&["commit-tree", &tree], Some(message.as_bytes()))?;
        // Refs sort by name, newest last: never the newest's millisecond again,
        // or two snapshots of one millisecond would sort by their ids.
        let after = newest
            .as_ref()
            .and_then(ref_ms)
            .map_or(0, |ms| ms.saturating_add(1));
        let refname = format!(
            "{REF_PREFIX}{:015}-{}",
            crate::time::now_ms().max(after),
            &commit[..commit.len().min(12)]
        );
        self.git.output(&["update-ref", &refname, &commit], None)?;
        self.find(&commit[..commit.len().min(12)]).map(Taken::New)
    }

    /// The files to keep, the paths left out and the bytes kept.
    fn select(&self, denied: &Denied, limits: Limits) -> Result<(Vec<String>, Vec<Omitted>, u64)> {
        let listed = self.listed_files()?;
        let mut kept = Vec::new();
        let mut omitted = Vec::new();
        let mut bytes = 0u64;
        for raw in listed.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let Ok(rel) = std::str::from_utf8(raw) else {
                omitted.push(omit(&String::from_utf8_lossy(raw), LeftOut::NameNotUtf8));
                continue;
            };
            if let Some(dir) = rel.strip_suffix('/') {
                omitted.push(omit(dir, LeftOut::NestedRepository));
                continue;
            }
            if !is_plain(rel) || in_state_folder(rel) {
                omitted.push(omit(rel, LeftOut::StateFolder));
                continue;
            }
            if denied.names(rel) {
                omitted.push(omit(rel, LeftOut::Denied));
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(self.project.join(rel)) else {
                // Gone since git listed it.
                continue;
            };
            if !(meta.is_file() || meta.file_type().is_symlink()) {
                omitted.push(omit(rel, LeftOut::NotAFile));
                continue;
            }
            if meta.is_file() && meta.len() > limits.file_bytes {
                omitted.push(omit(rel, LeftOut::TooLarge));
                continue;
            }
            bytes = bytes.saturating_add(meta.len());
            kept.push(rel.to_owned());
        }
        if kept.len() > limits.files {
            bail!(
                "no snapshot taken: the project has {} files to keep, more than the limit of {}; \
                 add the generated folders to .gitignore",
                kept.len(),
                limits.files
            );
        }
        if bytes > limits.total_bytes {
            bail!(
                "no snapshot taken: the project's files hold {} MiB, more than the limit of {} MiB; \
                 add the generated folders to .gitignore",
                bytes >> 20,
                limits.total_bytes >> 20
            );
        }
        Ok((kept, omitted, bytes))
    }

    /// Every file git would add, as `ls-files -z` prints it: the project's
    /// `.gitignore` files and its `.git/info/exclude` honoured, through an empty
    /// index of the listing's own so every file counts as new.
    fn listed_files(&self) -> Result<Vec<u8>> {
        self.list_others(&[])
    }

    /// The paths that exist and that the project's ignore rules leave out,
    /// sorted; a folder ignored as a whole is one entry ending in `/`.
    fn ignored_paths(&self) -> Result<Vec<String>> {
        let listed = self.list_others(&["--ignored", "--directory"])?;
        let mut paths: Vec<String> = listed
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        paths.sort();
        Ok(paths)
    }

    /// `ls-files -z --others --exclude-standard` and `extra` through an empty
    /// index of the listing's own.
    fn list_others(&self, extra: &[&str]) -> Result<Vec<u8>> {
        let index = private_name(&self.dir.join("openmoat-list-index"));
        let lister = self.git.with_index(index.clone());
        let exclude = self.project.join(".git").join("info").join("exclude");
        let exclude_setting = format!(
            "core.excludesFile={}",
            crate::context::path_string(&exclude)
        );
        let mut args = vec!["ls-files", "-z", "--others", "--exclude-standard"];
        args.extend_from_slice(extra);
        if exclude.is_file() {
            args.splice(0..0, ["-c", exclude_setting.as_str()]);
        }
        let files = lister.output(&args, None);
        let _ = fs::remove_file(&index);
        files
    }
}

/// Make `git`'s index hold exactly `kept`, reusing what git already hashed
/// for files that did not change.
fn stage(git: &ShadowGit, kept: &[String]) -> Result<()> {
    let cached = git.output(&["ls-files", "-z", "--cached"], None)?;
    let wanted: BTreeSet<&str> = kept.iter().map(String::as_str).collect();
    let stale: Vec<u8> = cached
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .filter(|p| std::str::from_utf8(p).map_or(true, |p| !wanted.contains(p)))
        .flat_map(|p| p.iter().copied().chain([0]))
        .collect();
    if !stale.is_empty() {
        git.output(
            &["update-index", "-z", "--force-remove", "--stdin"],
            Some(&stale),
        )?;
    }
    let list: Vec<u8> = kept.iter().flat_map(|p| p.bytes().chain([0])).collect();
    if !list.is_empty() {
        git.output(
            &["update-index", "-z", "--add", "--remove", "--stdin"],
            Some(&list),
        )?;
    }
    Ok(())
}

/// `path` with this process's id and the time added: a file no other
/// process uses.
fn private_name(path: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut name = path.as_os_str().to_owned();
    name.push(format!("-{}-{nanos}", std::process::id()));
    PathBuf::from(name)
}

fn remove_if_there(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Give `copy` the modification time of `original`.
fn keep_mtime(original: &Path, copy: &Path) -> std::io::Result<()> {
    let modified = fs::metadata(original)?.modified()?;
    fs::OpenOptions::new()
        .write(true)
        .open(copy)?
        .set_modified(modified)
}

/// The millisecond a snapshot's ref name starts with.
fn ref_ms(snapshot: &super::Listed) -> Option<i64> {
    let rest = snapshot.refname.strip_prefix(REF_PREFIX)?;
    rest.split('-').next()?.parse().ok()
}

fn omit(path: &str, why: LeftOut) -> Omitted {
    Omitted {
        path: path.to_owned(),
        why,
    }
}

/// The project-relative form of `path` under `root`, for paths a person names.
pub fn relative(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let text = crate::context::path_string(rel);
    is_plain(&text).then_some(text)
}
