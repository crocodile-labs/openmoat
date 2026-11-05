//! The lock as a person's command found it before asking its question.
//!
//! `openmoat allow --last` and `openmoat policy upgrade` check the lock, show
//! what they will do, wait for a `y`, write their files and re-pin. A re-pin
//! digests every pinned file afresh, so a pinned file changed while the
//! question waited (seconds, or minutes) would be pinned with nobody having
//! seen it. Such a command takes a [`Checkpoint`] with its drift check,
//! [`Checkpoint::verify`]s it once the answer is in, before it writes anything,
//! and re-pins with [`repin_after`], which verifies it again but for the files
//! the command wrote.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{Drift, HookPins, Lock, key, repin, split, verify_state};
use crate::home::Home;

/// The lock read just after the command found it intact; `None` when there
/// was none, as before the first `openmoat init`.
#[derive(Debug)]
pub struct Checkpoint(Option<Lock>);

impl Checkpoint {
    /// The lock on disk now. Take it right after the drift check, before the
    /// question.
    pub fn take(home: &Home) -> Result<Self> {
        let path = home.lock_path();
        if !path.exists() {
            return Ok(Self(None));
        }
        Ok(Self(Some(Lock::load(&path)?)))
    }

    /// Refuse when, since [`Self::take`], the lock itself changed or a file it
    /// pins changed, other than the files in `written` (the ones this command
    /// wrote) and drift the guard decides through anyway (a Claude Code setting
    /// `relaxed.rs` lists, which Claude Code may write while the person reads).
    /// Nothing new is asked: the refusal names the file, `openmoat doctor` shows it.
    pub fn verify(&self, home: &Home, written: &[PathBuf]) -> Result<()> {
        let Some(before) = &self.0 else {
            return Ok(());
        };
        let lock_path = home.lock_path();
        if !Lock::load(&lock_path).is_ok_and(|now| now == *before) {
            bail!(
                "refusing to re-pin: {} changed while OpenMoat waited for your answer, so it \
                 no longer pins what was checked; run `openmoat doctor` to see it",
                lock_path.display()
            );
        }
        let written: Vec<String> = written.iter().map(|p| key(p)).collect();
        let (drift, kept) = verify_state(home, before);
        let drift: Vec<Drift> = drift
            .into_iter()
            .filter(|d| !written.contains(&key(d.path())))
            .collect();
        if let Some(deny) = split(&kept, before, drift).deny {
            bail!(
                "refusing to re-pin: a pinned file changed while OpenMoat waited for your \
                 answer, and re-pinning now would accept it unseen ({}):\n  {}",
                super::INTEGRITY_RULE,
                deny.reasons.join("\n  ")
            );
        }
        Ok(())
    }
}

impl Drift {
    /// The pinned file this drift is about.
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::Modified(p)
            | Self::KeysChanged(p, _)
            | Self::Missing(p)
            | Self::Unreadable(p, _) => p,
            Self::Proposed { target, .. } => target,
        }
    }
}

/// [`repin`] once `checkpoint` still holds for every pinned file but `written`.
pub fn repin_after(
    home: &Home,
    binary: &Path,
    hooks: HookPins,
    checkpoint: &Checkpoint,
    written: &[PathBuf],
) -> Result<Lock> {
    checkpoint.verify(home, written)?;
    repin(home, binary, hooks)
}

#[cfg(test)]
mod tests;
