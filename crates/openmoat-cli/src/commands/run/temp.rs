//! The temp directory of one `moat run`: a new directory of its own (mode
//! `0700`) inside the system's, which the sandbox lets commands write and the
//! agent gets as `TMPDIR`. The shared temp directory (`/tmp` on Linux) holds
//! other programs' state, other sessions' files and Kerberos tickets; it is
//! no longer granted, so nothing the agent's commands write lands there and
//! nothing they leave there survives the run. Removed when the run ends.
//!
//! Under `--isolate` the whole temp directory is an empty `tmpfs` already,
//! private to the session, so this is not used there.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::context::path_string;
use crate::guard_relay::random_hex;

/// The variable programs take their temp directory from.
pub const TMPDIR: &str = "TMPDIR";

/// The run's own temp directory; removed with everything in it when dropped.
#[derive(Debug)]
pub struct RunTemp {
    dir: PathBuf,
}

impl RunTemp {
    /// A new directory `openmoat-run-<random>` in the system's temp directory,
    /// resolved. Fails rather than reuse one that exists.
    pub fn create() -> Result<Self> {
        let system =
            std::fs::canonicalize(std::env::temp_dir()).context("resolving the temp directory")?;
        Self::create_in(&system)
    }

    fn create_in(system: &Path) -> Result<Self> {
        let name = format!("openmoat-run-{}", random_hex(8)?.as_str());
        let dir = system.join(name);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&dir)
            .with_context(|| format!("creating the run's temp directory {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// Its path, slash-separated.
    pub fn path(&self) -> String {
        path_string(&self.dir)
    }
}

impl Drop for RunTemp {
    fn drop(&mut self) {
        // `remove_dir_all` does not follow links a command left inside.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_run_gets_a_new_private_directory_removed_afterwards() {
        let base = tempfile::tempdir().unwrap();
        let first = RunTemp::create_in(base.path()).unwrap();
        let second = RunTemp::create_in(base.path()).unwrap();
        assert_ne!(first.path(), second.path());
        let dir = PathBuf::from(first.path());
        assert!(dir.starts_with(base.path()));
        assert!(
            dir.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("openmoat-run-"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::write(dir.join("left.txt"), "x").unwrap();
        drop(first);
        assert!(!dir.exists(), "removed with what is inside");
        assert!(PathBuf::from(second.path()).is_dir());
    }
}
