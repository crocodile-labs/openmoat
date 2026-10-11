//! The kernel's own state directory (`~/.moat`, or `$MOAT_HOME`).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{DEFAULT_POLICY, Policy};

use crate::context;

/// The state directory's name under the home directory, and under a project
/// for its repository policy (`repo.rs`).
pub const DIR_NAME: &str = ".moat";

/// The environment variable that moves the state directory.
pub const ENV: &str = "MOAT_HOME";

#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// Locate the state directory without creating it.
    pub fn locate() -> Result<Self> {
        match std::env::var_os(ENV).filter(|v| !v.is_empty()) {
            Some(custom) => Ok(Self {
                root: PathBuf::from(custom),
            }),
            None => Ok(Self::under(&user_home()?)),
        }
    }

    /// The default state directory of a person whose home directory is `home`.
    pub fn under(home: &Path) -> Self {
        Self {
            root: home.join(DIR_NAME),
        }
    }

    /// A state directory at `root`, for unit tests.
    #[cfg(test)]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The configuration directory of each agent `moat init` set up.
    pub fn hosts_path(&self) -> PathBuf {
        self.root.join("hosts.json")
    }

    pub fn policy_path(&self) -> PathBuf {
        self.root.join("policy.yaml")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.db")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root.join("policy.lock")
    }

    pub fn environment_path(&self) -> PathBuf {
        self.root.join("environment.json")
    }

    pub fn grants_path(&self) -> PathBuf {
        self.root.join("approvals.json")
    }

    pub fn overlay_path(&self) -> PathBuf {
        self.root.join("policy.d").join("approved.yaml")
    }

    pub fn trust_path(&self) -> PathBuf {
        self.root.join("trust.json")
    }

    /// Calls the guard denied because no decision came in time (`hangs.rs`).
    pub fn hangs_path(&self) -> PathBuf {
        self.root.join("guard-hangs.log")
    }

    pub fn exists(&self) -> bool {
        self.root.is_dir()
    }

    /// Create the directory with owner-only permissions, tightening an
    /// existing one.
    pub fn ensure(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        #[cfg(unix)]
        restrict(&self.root, PRIVATE_DIR)?;
        Ok(())
    }

    /// Write the default policy unless one is already present. Returns `true` if written.
    pub fn ensure_policy(&self) -> Result<bool> {
        let path = self.policy_path();
        if path.exists() {
            return Ok(false);
        }
        write_private(&path, DEFAULT_POLICY.as_bytes())?;
        Ok(true)
    }

    /// Load and lint the installed user policy, with `moat allow` rules merged in.
    pub fn load_policy(&self) -> Result<Policy> {
        let path = self.policy_path();
        if !path.is_file() {
            bail!("no policy at {}; run `moat init`", path.display());
        }
        self.load_policy_at(&path)
    }

    /// Load and lint the policy file at `path` as if it were installed, with
    /// `moat allow` rules merged in (`moat edit` checks its draft this way).
    pub fn load_policy_at(&self, path: &Path) -> Result<Policy> {
        let mut policy = context::load_policy(path)?;
        let overlay = crate::approvals::Overlay::load(&self.overlay_path())?;
        if !overlay.allow.is_empty() {
            policy.allow.extend(overlay.allow);
            policy
                .lint()
                .with_context(|| format!("merging {}", self.overlay_path().display()))?;
        }
        Ok(policy)
    }

    /// The audit log, read-only; an error naming `moat init` when it is missing.
    pub fn open_audit(&self) -> Result<openmoat_audit::Store> {
        let path = self.audit_path();
        if !path.is_file() {
            bail!("no audit log at {}; run `moat init`", path.display());
        }
        openmoat_audit::Store::open_read_only(&path)
            .with_context(|| format!("opening {}", path.display()))
    }

    /// Create empty approval files so the lock covers them from the first run.
    pub fn ensure_approval_files(&self) -> Result<()> {
        if !self.grants_path().exists() {
            crate::approvals::Grants::default().save(&self.grants_path(), crate::time::now_ms())?;
        }
        if !self.overlay_path().exists() {
            crate::approvals::Overlay::default().save(&self.overlay_path())?;
        }
        Ok(())
    }
}

/// Write a file atomically with owner-only permissions.
///
/// The temporary file is created owner-only before any byte is written, so the
/// contents are never readable by others, not even between write and rename.
/// Missing parent directories are created owner-only too.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    create_private_dir(parent)?;
    // The time keeps a temporary file left by a crashed run with the same
    // process id from making this one fail.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{nanos}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    let written = (|| {
        let mut file = private_file_options()
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

pub fn user_home() -> Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(home) => Ok(PathBuf::from(home)),
        None => bail!("{var} is not set"),
    }
}

#[cfg(unix)]
const PRIVATE_DIR: u32 = 0o700;

/// `create_dir_all` whose new directories are owner-only (Unix).
fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, PRIVATE_DIR);
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Options for a new file that is owner-only from the moment it exists (Unix).
fn private_file_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Options that append to a file, creating it owner-only (Unix).
pub fn private_append_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Set Unix permission bits. Unix only: elsewhere the profile directory's ACL
/// already limits access to the user.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting permissions of {}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn private_files_and_their_new_parents_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.d/approved.yaml");
        write_private(&file, b"x").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"x");
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
        write_private(&file, b"y").unwrap();
        assert_eq!(
            (fs::read(&file).unwrap(), mode(&file)),
            (b"y".to_vec(), 0o600)
        );
        let leftovers = fs::read_dir(file.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "no temporary file is left behind");
    }

    #[test]
    fn a_temporary_file_left_by_a_crash_does_not_block_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hosts.json");
        let stale = dir
            .path()
            .join(format!(".hosts.json.tmp-{}", std::process::id()));
        fs::write(&stale, b"old").unwrap();
        write_private(&file, b"new").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"new");
    }

    #[test]
    fn ensure_tightens_an_existing_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(".moat");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Home { root: root.clone() }.ensure().unwrap();
        assert_eq!(mode(&root), 0o700);
    }
}
