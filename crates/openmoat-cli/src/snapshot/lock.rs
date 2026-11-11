//! One process at a time changes a store (ADR-085 §6).
//!
//! Two `openmoat run` in one project, or a run and a person's `openmoat
//! snapshot` or `restore`, would otherwise race: a prune's `gc` could drop the
//! objects another take had written but not yet pointed a ref at, and two
//! takes would fight over one index. Taking, pruning and restoring hold the
//! store's lock file (`openmoat.lock`, an OS file lock, let go when the
//! process ends however it ends); listing and planning only read.

use std::fs::{File, TryLockError};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};

use super::Store;

/// The lock file in each store.
const LOCK_FILE: &str = "openmoat.lock";

/// How long a take, prune or restore waits for another to finish.
pub const WAIT: Duration = Duration::from_secs(10);

/// How often a waiting process tries again.
const POLL: Duration = Duration::from_millis(25);

/// The store's lock, held until dropped.
#[derive(Debug)]
pub struct Held {
    _file: File,
    dir: PathBuf,
}

impl Store {
    /// Hold the store's lock, waiting up to `wait` for another process that
    /// holds it.
    pub fn lock(&self, wait: Duration) -> Result<Held> {
        let path = self.dir.join(LOCK_FILE);
        let file = crate::home::private_append_options()
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Held {
                        _file: file,
                        dir: self.dir.clone(),
                    });
                }
                Err(TryLockError::WouldBlock) if started.elapsed() < wait => {
                    std::thread::sleep(POLL);
                }
                Err(TryLockError::WouldBlock) => bail!(
                    "another `openmoat run`, `openmoat snapshot` or `openmoat restore` is using \
                     the snapshot store of {}; try again when it is done",
                    self.project.display()
                ),
                Err(TryLockError::Error(e)) => {
                    return Err(e).context("locking the snapshot store");
                }
            }
        }
    }

    /// An error unless `held` is this store's lock.
    pub(super) fn check_held(&self, held: &Held) -> Result<()> {
        ensure!(
            held.dir == self.dir,
            "the lock held is another snapshot store's"
        );
        Ok(())
    }
}
