//! git on the shadow store, with nothing of the project's or the person's
//! git configuration (ADR-085 §1).
//!
//! Every command starts from an empty environment: `GIT_DIR` is the store,
//! `GIT_WORK_TREE` the project, `GIT_INDEX_FILE` an index inside the store, and
//! the system and global configuration files are `/dev/null`. The project's own
//! `.git` (its config, hooks, index, `HEAD`) is never read or written, so a
//! `core.fsmonitor`, a filter driver or a hook it names never runs. A
//! `.gitattributes` in the project can name a filter, but no configuration
//! defines one, so git stores the bytes as they are. Only plumbing commands
//! run (`ls-files`, `update-index`, `write-tree`, `commit-tree`, `update-ref`,
//! `for-each-ref`, `diff-tree`, `cat-file`, `gc`): none of them runs a hook.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

/// The configuration every command gets on its command line, after the
/// empty system and global files: no hooks, no file system monitor, no
/// untracked cache, paths printed as they are, and no automatic `gc` in the
/// middle of a snapshot.
const CONFIG: &[&str] = &[
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.untrackedCache=false",
    "core.quotePath=false",
    "core.bare=false",
    "core.symlinks=true",
    "core.autocrlf=false",
    "gc.auto=0",
    "commit.gpgSign=false",
];

/// The name and address git writes into a snapshot commit.
const IDENTITY: (&str, &str) = ("OpenMoat", "snapshot@openmoat.invalid");

/// The empty configuration file of each level OpenMoat does not set.
#[cfg(windows)]
const NO_CONFIG: &str = "NUL";
#[cfg(not(windows))]
const NO_CONFIG: &str = "/dev/null";

/// git on one store for one project.
#[derive(Debug, Clone)]
pub struct ShadowGit {
    /// The `git` the environment snapshot `openmoat init` recorded, by its
    /// absolute path: never one the project's `PATH` entries could name.
    program: PathBuf,
    store: PathBuf,
    work_tree: PathBuf,
    index: PathBuf,
}

impl ShadowGit {
    pub fn new(program: PathBuf, store: PathBuf, work_tree: PathBuf) -> Self {
        let index = store.join("openmoat-index");
        Self {
            program,
            store,
            work_tree,
            index,
        }
    }

    /// The same git with another index file (a throwaway one for listing).
    pub fn with_index(&self, index: PathBuf) -> Self {
        Self {
            index,
            ..self.clone()
        }
    }

    /// Create the store as a bare repository without the template's sample hooks.
    pub fn init(&self) -> Result<()> {
        let mut cmd = self.base();
        cmd.arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg("--template=")
            .arg(&self.store);
        let out = run(cmd, None)?;
        if !out.ok {
            bail!(
                "git could not create the snapshot store {}: {}",
                self.store.display(),
                out.error
            );
        }
        Ok(())
    }

    /// `git <args>` on the store and the project, `stdin` written to it; its
    /// standard output when it succeeds.
    pub fn output(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let out = self.raw(args, stdin)?;
        if !out.ok {
            bail!(
                "git {} failed on the snapshot store {}: {}",
                args.first().copied().unwrap_or_default(),
                self.store.display(),
                out.error
            );
        }
        Ok(out.stdout)
    }

    /// [`ShadowGit::output`] as text, trimmed.
    pub fn text(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
        let bytes = self.output(args, stdin)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
    }

    /// `git <args>` whatever its exit status.
    pub fn raw(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Out> {
        let mut cmd = self.base();
        cmd.env("GIT_DIR", &self.store)
            .env("GIT_WORK_TREE", &self.work_tree)
            .env("GIT_INDEX_FILE", &self.index)
            .env("GIT_AUTHOR_NAME", IDENTITY.0)
            .env("GIT_AUTHOR_EMAIL", IDENTITY.1)
            .env("GIT_COMMITTER_NAME", IDENTITY.0)
            .env("GIT_COMMITTER_EMAIL", IDENTITY.1)
            .current_dir(&self.work_tree)
            .args(args);
        run(cmd, stdin)
    }

    /// git with the hardened environment and configuration, before its subcommand.
    fn base(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.env_clear()
            .env("PATH", search_path(&self.program))
            .env("HOME", &self.store)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", NO_CONFIG)
            .env("GIT_CONFIG_GLOBAL", NO_CONFIG)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_ATTR_NOSYSTEM", "1");
        // Windows cannot start processes without these.
        for var in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if cfg!(windows)
                && let Some(value) = std::env::var_os(var)
            {
                cmd.env(var, value);
            }
        }
        cmd.arg("--no-pager");
        for setting in CONFIG {
            cmd.arg("-c").arg(setting);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
}

/// What one git command printed and whether it succeeded.
pub struct Out {
    pub ok: bool,
    pub stdout: Vec<u8>,
    /// The first line of what it printed on stderr.
    pub error: String,
}

/// The directory of the pinned git and the system directories, nothing the
/// environment adds: git finds its own helpers from where it is installed.
fn search_path(program: &Path) -> OsString {
    let mut dirs: Vec<PathBuf> = program
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    if !cfg!(windows) {
        dirs.extend(["/usr/bin", "/bin"].map(PathBuf::from));
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

fn run(mut cmd: Command, stdin: Option<&[u8]>) -> Result<Out> {
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().context("starting git for the snapshot store")?;
    let writer = match (stdin, child.stdin.take()) {
        (Some(bytes), Some(mut pipe)) => {
            let bytes = bytes.to_vec();
            Some(std::thread::spawn(move || pipe.write_all(&bytes)))
        }
        _ => None,
    };
    let mut stderr = Vec::new();
    let reader = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let _ = pipe.read_to_end(&mut stderr);
            stderr
        })
    });
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout)
            .context("reading git's output")?;
    }
    let status = child.wait().context("waiting for git")?;
    if let Some(writer) = writer {
        // git may stop reading early when it fails; its status says so.
        let _ = writer.join();
    }
    let stderr = reader.and_then(|r| r.join().ok()).unwrap_or_default();
    let error = String::from_utf8_lossy(&stderr)
        .lines()
        .next()
        .unwrap_or("no message")
        .to_owned();
    Ok(Out {
        ok: status.success(),
        stdout,
        error,
    })
}
