//! The private copy of a `command` source's program that the proxy runs
//! (ADR-087): the bytes it hashed, not the file at the path, which could be
//! swapped between the hash and the start.
//!
//! The copy lives in `secret-programs/` under OpenMoat's state directory, an
//! owner-only folder the agent cannot write (`kernel-self`), as an owner-only
//! file, and is removed when the proxy ends.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, ensure};

/// A program's bytes, written once to a private file.
pub struct Copy {
    path: PathBuf,
    digest: String,
}

impl Copy {
    /// Read `program` once, and write what was read to a private file for
    /// secret `id` under `state`; `digest` is the SHA-256 of those bytes.
    pub fn make(program: &Path, id: &str, state: &Path) -> Result<Self> {
        static MADE: AtomicU64 = AtomicU64::new(0);
        let bytes =
            std::fs::read(program).with_context(|| format!("reading {}", program.display()))?;
        let digest = crate::integrity::sha256_hex(&bytes);
        let dir = state.join("secret-programs");
        crate::home::create_private_dir(&dir)?;
        let n = MADE.fetch_add(1, Ordering::Relaxed);
        let mut name = format!("{}-{n}-{id}", std::process::id());
        if let Some(ext) = program.extension().and_then(|e| e.to_str()) {
            // Windows starts a program by its extension.
            name = format!("{name}.{ext}");
        }
        let path = dir.join(name);
        // One left by an earlier proxy with the same process id.
        let _ = std::fs::remove_file(&path);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o700);
        let mut file = options
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("writing {}", path.display()))?;
        drop(file);
        let copy = Self { path, digest };
        copy.verify()?;
        Ok(copy)
    }

    /// The file to run.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// SHA-256 of the program as it was read.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Refused when the copy is no longer the bytes that were hashed.
    pub fn verify(&self) -> Result<()> {
        let now = super::program::digest(&self.path)?;
        ensure!(
            now == self.digest,
            "the private copy {} changed; restart `openmoat proxy`",
            self.path.display()
        );
        Ok(())
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
