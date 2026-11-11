//! Taking a snapshot: list the project's files as git sees them (its
//! `.gitignore` files and `.git/info/exclude` honoured), leave out what a
//! deny rule names and what is too large, and commit the rest to the store.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{AtomicAction, CompiledPolicy, EvalContext, Policy, Verdict};

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
    /// Take a snapshot of the project now.
    pub fn take(
        &self,
        denied: &Denied,
        limits: Limits,
        reason: Reason,
        session: Option<&str>,
    ) -> Result<Taken> {
        if self.git.pin_attributes()? {
            // Its entries may hold blobs the project's attributes converted.
            match fs::remove_file(self.git.index()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).context("starting the snapshot index again");
                }
                _ => {}
            }
        }
        let (kept, mut omitted, bytes) = self.select(denied, limits)?;
        let left_out_total = omitted.len();
        omitted.truncate(MAX_LISTED);
        self.stage(&kept)?;
        let tree = self.git.text(&["write-tree"], None)?;
        let meta = Meta {
            version: META_VERSION,
            reason,
            session: session.map(str::to_owned),
            files: kept.len(),
            bytes,
            left_out: omitted,
            left_out_total,
        };
        if let Some(newest) = self.list()?.pop()
            && newest.tree == tree
            && newest.meta.left_out == meta.left_out
        {
            return Ok(Taken::Unchanged(newest));
        }
        let message = serde_json::to_string(&meta)?;
        let commit = self
            .git
            .text(&["commit-tree", &tree], Some(message.as_bytes()))?;
        let refname = format!(
            "{REF_PREFIX}{:015}-{}",
            crate::time::now_ms(),
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
        let index = self.dir.join("openmoat-list-index");
        let _ = fs::remove_file(&index);
        let lister = self.git.with_index(index.clone());
        let exclude = self.project.join(".git").join("info").join("exclude");
        let exclude_setting = format!(
            "core.excludesFile={}",
            crate::context::path_string(&exclude)
        );
        let mut args = vec!["ls-files", "-z", "--others", "--exclude-standard"];
        if exclude.is_file() {
            args.splice(0..0, ["-c", exclude_setting.as_str()]);
        }
        let files = lister.output(&args, None);
        let _ = fs::remove_file(&index);
        files
    }

    /// Make the store's index hold exactly `kept`, reusing what git already
    /// hashed for files that did not change.
    fn stage(&self, kept: &[String]) -> Result<()> {
        let cached = self.git.output(&["ls-files", "-z", "--cached"], None)?;
        let wanted: BTreeSet<&str> = kept.iter().map(String::as_str).collect();
        let stale: Vec<u8> = cached
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .filter(|p| std::str::from_utf8(p).map_or(true, |p| !wanted.contains(p)))
            .flat_map(|p| p.iter().copied().chain([0]))
            .collect();
        if !stale.is_empty() {
            self.git.output(
                &["update-index", "-z", "--force-remove", "--stdin"],
                Some(&stale),
            )?;
        }
        let list: Vec<u8> = kept.iter().flat_map(|p| p.bytes().chain([0])).collect();
        if !list.is_empty() {
            self.git.output(
                &["update-index", "-z", "--add", "--remove", "--stdin"],
                Some(&list),
            )?;
        }
        Ok(())
    }
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
