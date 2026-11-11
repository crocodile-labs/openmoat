//! Workspace snapshots in a shadow git store, and what `openmoat restore`
//! puts back from them (ADR-085).
//!
//! Each project has its own store under the state directory,
//! `snapshots/<first 32 hex of the SHA-256 of the project's real path>/`, a bare
//! git repository the agent cannot reach: `kernel-self` denies reading and
//! writing it, and every OpenMoat sandbox keeps the state directory out. Only
//! OpenMoat's own processes started by a person write it: `openmoat run`
//! outside its sandbox, before the agent starts and after it exits, and
//! `openmoat snapshot` and `openmoat restore` at a person's terminal.
//!
//! A snapshot is a commit (no parent) of the project's files on a ref
//! `refs/openmoat/snapshots/<ms>-<id>`, whose message is a JSON [`Meta`]: why
//! it was taken, by which run, and every path it left out and why.

mod capture;
mod git;
mod lock;
mod paths;
mod restore;
mod retention;
mod session;

#[cfg(test)]
mod tests;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::home::{Home, write_private};
pub use capture::{Limits, Taken, relative};
use git::ShadowGit;
pub use lock::WAIT as LOCK_WAIT;
pub use restore::{ChangeKind, Plan};
pub use retention::Retention;
pub use session::{RunSnapshots, denied, said};

/// The folder of the state directory that holds every project's store.
pub const DIR: &str = "snapshots";
/// The ref namespace of the snapshots in a store.
const REF_PREFIX: &str = "refs/openmoat/snapshots/";
/// The file in a store naming the project it is for.
const PROJECT_FILE: &str = "openmoat-project";
/// The version of [`Meta`] this build writes and reads.
const META_VERSION: u32 = 1;

/// Why a snapshot was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// `openmoat run`, before the agent started.
    RunStart,
    /// `openmoat run`, after the agent exited.
    RunExit,
    /// `openmoat snapshot`, by a person.
    Manual,
    /// `openmoat restore`, of the state it was about to change.
    PreRestore,
}

impl Reason {
    pub fn words(self) -> &'static str {
        match self {
            Self::RunStart => "before the agent started",
            Self::RunExit => "after the agent exited",
            Self::Manual => "taken by hand",
            Self::PreRestore => "before a restore",
        }
    }
}

/// Why a path is not in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeftOut {
    /// A deny rule names it (a secret, OpenMoat's or an agent's own files).
    Denied,
    /// Larger than [`Limits::file_bytes`].
    TooLarge,
    /// A git repository of its own inside the project.
    NestedRepository,
    /// Not a regular file or a symbolic link (a socket, a pipe, a device).
    NotAFile,
    /// Its name is not UTF-8.
    NameNotUtf8,
    /// Inside `.git` or `.moat`.
    StateFolder,
}

impl LeftOut {
    pub fn words(self) -> &'static str {
        match self {
            Self::Denied => "a deny rule names it",
            Self::TooLarge => "larger than the size limit",
            Self::NestedRepository => "a git repository of its own",
            Self::NotAFile => "not a file or a link",
            Self::NameNotUtf8 => "its name is not UTF-8",
            Self::StateFolder => "inside .git or .moat",
        }
    }
}

/// One path a snapshot left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omitted {
    pub path: String,
    pub why: LeftOut,
}

/// What a snapshot's commit message holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub version: u32,
    pub reason: Reason,
    /// The `openmoat run` session it belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub files: usize,
    pub bytes: u64,
    /// The paths left out, at most [`capture::MAX_LISTED`] of them.
    pub left_out: Vec<Omitted>,
    /// How many paths were left out in all; more than `left_out` holds when
    /// the list was cut.
    pub left_out_total: usize,
    /// The paths that existed and that the project's ignore rules left out,
    /// a folder ignored as a whole as one entry ending in `/`; at most
    /// [`capture::MAX_LISTED`]. A restore never deletes one of them: the
    /// snapshot does not say what they held.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
    /// How many such paths there were in all.
    #[serde(default)]
    pub ignored_total: usize,
}

impl Meta {
    /// Whether `left_out` names every path the snapshot left out.
    pub fn lists_all_left_out(&self) -> bool {
        self.left_out.len() == self.left_out_total
    }

    /// Whether `path` was there and ignored when the snapshot was taken, or
    /// may have been: the list of ignored paths was cut.
    pub fn may_have_ignored(&self, path: &str) -> bool {
        if self.ignored.len() != self.ignored_total {
            return true;
        }
        let listed = |p: &str| self.ignored.binary_search_by(|i| i.as_str().cmp(p)).is_ok();
        listed(path) || path.match_indices('/').any(|(at, _)| listed(&path[..=at]))
    }
}

/// One snapshot in a store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listed {
    /// The first 12 hex characters of its commit: what a person types.
    pub id: String,
    #[serde(skip)]
    pub commit: String,
    #[serde(skip)]
    pub tree: String,
    #[serde(skip)]
    pub refname: String,
    pub ts_ms: i64,
    pub meta: Meta,
}

/// The shadow store of one project.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    /// The project's real path, the store's work tree.
    project: PathBuf,
    git: ShadowGit,
}

impl Store {
    /// The store of `project` in `home`, created on first use with owner-only
    /// permissions. git is the one the environment snapshot `openmoat init`
    /// recorded; without one no snapshot is taken.
    pub fn open(home: &Home, project: &Path) -> Result<Self> {
        let store = Self::at(home, project)?;
        if !store.dir.join("HEAD").is_file() {
            write_private(
                &store.dir.join(PROJECT_FILE),
                format!("{}\n", store.project.display()).as_bytes(),
            )?;
            store.git.init()?;
        }
        Ok(store)
    }

    /// The store of `project` when it exists: `None` when no snapshot was ever taken.
    pub fn existing(home: &Home, project: &Path) -> Result<Option<Self>> {
        let store = Self::at(home, project)?;
        Ok(store.dir.join("HEAD").is_file().then_some(store))
    }

    fn at(home: &Home, project: &Path) -> Result<Self> {
        let project = std::fs::canonicalize(project)
            .with_context(|| format!("resolving the project {}", project.display()))?;
        let program = crate::environment::program(home, "git").context(
            "no git with an absolute path is in the search path `openmoat init` recorded; \
             snapshots need git",
        )?;
        let dir = home.root().join(DIR).join(store_name(&project));
        let git = ShadowGit::new(program, dir.clone(), project.clone());
        Ok(Self { dir, project, git })
    }

    pub fn project(&self) -> &Path {
        &self.project
    }

    /// Every snapshot, oldest first.
    pub fn list(&self) -> Result<Vec<Listed>> {
        let text = self.git.output(
            &[
                "for-each-ref",
                "--sort=refname",
                "--format=%(refname)%00%(objectname)%00%(tree)%00%(committerdate:unix)%00%(contents)%00",
                REF_PREFIX,
            ],
            None,
        )?;
        parse_listing(&String::from_utf8_lossy(&text))
    }

    /// The snapshot `id` names: a prefix of its commit, at least 4 characters,
    /// that only one snapshot has.
    pub fn find(&self, id: &str) -> Result<Listed> {
        if id.len() < 4 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("`{id}` is not a snapshot id: `openmoat snapshot --list` shows them");
        }
        let id = id.to_ascii_lowercase();
        let mut found = self
            .list()?
            .into_iter()
            .filter(|s| s.commit.starts_with(&id));
        match (found.next(), found.next()) {
            (Some(one), None) => Ok(one),
            (Some(_), Some(_)) => bail!("`{id}` names more than one snapshot; give more of it"),
            (None, _) => bail!("no snapshot `{id}` of this project: `openmoat snapshot --list`"),
        }
    }
}

/// The store's folder name for the project at `real`.
fn store_name(real: &Path) -> String {
    let digest = Sha256::digest(crate::context::path_string(real).as_bytes());
    digest[..16].iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

/// `for-each-ref`'s records: five NUL-ended fields each, then a line break.
fn parse_listing(text: &str) -> Result<Vec<Listed>> {
    let mut fields = text.split('\0');
    let mut listed = Vec::new();
    while let Some(refname) = fields.next().map(str::trim) {
        if refname.is_empty() {
            break;
        }
        let (Some(commit), Some(tree), Some(time), Some(message)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            bail!("the snapshot store lists {refname} incompletely");
        };
        let meta: Meta = serde_json::from_str(message.trim())
            .with_context(|| format!("reading snapshot {refname}"))?;
        if meta.version != META_VERSION {
            bail!(
                "snapshot {refname} has version {}; this build reads {META_VERSION}",
                meta.version
            );
        }
        let secs: i64 = time.trim().parse().unwrap_or_default();
        listed.push(Listed {
            id: commit.chars().take(12).collect(),
            commit: commit.to_owned(),
            tree: tree.to_owned(),
            refname: refname.to_owned(),
            ts_ms: secs.saturating_mul(1000),
            meta,
        });
    }
    Ok(listed)
}

/// Record what OpenMoat did to the project's files in the audit log, as an
/// event of host `openmoat`. A log that cannot be written is said on stderr:
/// the snapshot or restore itself stands.
pub fn record(home: &Home, session: &str, tool: &str, rule: &str, reason: String) {
    let decision = openmoat_core::Decision::single(openmoat_core::Verdict::Allow, rule, reason);
    let written = openmoat_audit::Store::open_existing(&home.audit_path()).and_then(|store| {
        store.record(&openmoat_audit::NewEvent {
            host: "openmoat",
            session_id: session,
            call_id: None,
            cwd: None,
            tool,
            action: None,
            decision: &decision,
            latency_us: 0,
        })
    });
    if let Err(error) = written {
        eprintln!("openmoat: the audit log did not record the {tool}: {error}");
    }
}
