//! The bytes the lock check read, kept so the guard uses exactly what matched
//! each pin, and sorts settings drift by exactly what was found to differ,
//! even when a file changes after the check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::digest::{ReadOnce, is_claude_settings};
use super::{Drift, Lock, key, keys, spec_keys};
use crate::home::Home;

/// The pin of a state file that was missing when a person re-pinned: one
/// that appears there later is drift, never a file read unpinned from disk.
/// No SHA-256 digest is this word.
pub(super) const ABSENT: &str = "absent";

/// Pinned files' bytes as [`Lock::verify_keeping`] read them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Kept {
    /// Each requested file that is pinned and intact, under the path it was
    /// requested by, with the bytes that matched its pin.
    intact: BTreeMap<PathBuf, Vec<u8>>,
    /// Each Claude Code settings file, or hook file with relaxed keys
    /// (`spec_keys.rs`), whose top-level keys drifted and that is a regular
    /// file, under the path its drift names, with the bytes read.
    drifted: BTreeMap<PathBuf, Vec<u8>>,
}

impl Kept {
    /// The bytes of the pinned file requested as `path` that matched its pin;
    /// `None` when it was not requested, is not pinned or drifted.
    pub fn get(&self, path: &Path) -> Option<&[u8]> {
        self.intact.get(path).map(Vec::as_slice)
    }

    /// The bytes of the drifted settings file `path` names in its drift.
    pub(super) fn drifted(&self, path: &Path) -> Option<&[u8]> {
        self.drifted.get(path).map(Vec::as_slice)
    }
}

/// [`Lock::verify_keeping`] of OpenMoat's own state files and installed packs
/// (what `moat guard` decides by), with `home` reading each one that matched
/// its pin from the bytes that matched instead of from disk.
pub fn verify_state(home: &Home, lock: &Lock) -> (Vec<Drift>, Home) {
    let mut files = super::state_files(home);
    files.push(home.packs_path());
    let (drift, kept) = lock.verify_keeping(&files, &[home.packs_dir()]);
    (drift, home.keeping(kept))
}

impl Lock {
    /// [`Lock::verify`], also returning the bytes checked: of each pinned and
    /// intact file in `files` or directly in one of `dirs` (kept under the path
    /// requested: the file itself, or the directory joined with its name), and
    /// of each settings file whose keys drifted (`drifted`). Each file is read
    /// once, so a caller that parses these bytes uses exactly what was checked,
    /// even when the file changes after the check.
    pub fn verify_keeping(&self, files: &[PathBuf], dirs: &[PathBuf]) -> (Vec<Drift>, Kept) {
        let wanted: BTreeMap<String, &PathBuf> = files.iter().map(|p| (key(p), p)).collect();
        // A directory's key is its canonical form, as the key of a file in it has.
        let dirs: Vec<(PathBuf, &PathBuf)> = dirs
            .iter()
            .filter_map(|d| Some((PathBuf::from(key(&d.join("x"))).parent()?.to_owned(), d)))
            .collect();
        let requested = |stored: &str| -> Option<PathBuf> {
            if let Some(path) = wanted.get(stored) {
                return Some((*path).clone());
            }
            let stored = Path::new(stored);
            let (parent, name) = (stored.parent()?, stored.file_name()?);
            let (_, dir) = dirs.iter().find(|(canonical, _)| canonical == parent)?;
            Some(dir.join(name))
        };
        let mut kept = Kept::default();
        let mut drift = Vec::new();
        for (stored, expected) in &self.entries {
            // A stored key is canonical as of pinning. If it no longer maps to
            // itself, a directory on the way was moved or replaced by a link:
            // the file the kernel will read is not the one that was pinned.
            if key(Path::new(stored)) != *stored {
                drift.push(Drift::Modified(PathBuf::from(stored)));
                continue;
            }
            match self.check_one(Path::new(stored), expected) {
                Ok(read) => {
                    if let (Some(path), Some(read)) = (requested(stored), read) {
                        kept.intact.insert(path, read.contents);
                    }
                }
                Err((found, read)) => {
                    if let (Drift::KeysChanged(path, _), Some(read)) = (&found, read)
                        && read.regular
                        && (is_claude_settings(path) || spec_keys::listed(path).is_some())
                    {
                        kept.drifted.insert(path.clone(), read.contents);
                    }
                    drift.push(found);
                }
            }
        }
        drift.extend(self.codex_drift());
        (drift, kept)
    }

    /// Drift of the Codex profiles the lock pins.
    fn codex_drift(&self) -> impl Iterator<Item = Drift> + '_ {
        self.codex_profiles.iter().filter_map(|(stored, expected)| {
            let path = PathBuf::from(stored);
            if key(&path) != *stored {
                return Some(Drift::Modified(path));
            }
            if fs::symlink_metadata(&path).is_err() {
                return Some(Drift::Missing(path));
            }
            match crate::sandbox::install::codex_part_digest(&path) {
                Ok(actual) if &actual == expected => None,
                Ok(_) => Some(Drift::Modified(path)),
                Err(e) => Some(Drift::Unreadable(path, format!("{e:#}"))),
            }
        })
    }

    /// The pinned file at `path`, read once and matching `expected` (`None`
    /// for a file pinned as [`ABSENT`] that is still missing), or how it
    /// differs with what was read, if it could be.
    pub(super) fn check_one(
        &self,
        path: &Path,
        expected: &str,
    ) -> Result<Option<ReadOnce>, (Drift, Option<ReadOnce>)> {
        if fs::symlink_metadata(path).is_err() {
            if expected == ABSENT {
                return Ok(None);
            }
            return Err((Drift::Missing(path.to_path_buf()), None));
        }
        let read = ReadOnce::from(path).map_err(|e| {
            (
                Drift::Unreadable(path.to_path_buf(), format!("{e:#}")),
                None,
            )
        })?;
        if read
            .digests(is_claude_settings(path), self.form(&key(path)))
            .iter()
            .any(|d| d == expected)
        {
            Ok(Some(read))
        } else {
            Err((
                self.modified(path.to_path_buf(), &read.contents),
                Some(read),
            ))
        }
    }

    /// [`Drift::KeysChanged`] when the pin recorded the file's top-level keys
    /// and some differ in `contents`, else [`Drift::Modified`].
    fn modified(&self, path: PathBuf, contents: &[u8]) -> Drift {
        let now = keys::key_digests_of(&path, contents);
        let pinned = self.keys.get(&key(&path));
        match pinned.zip(now).and_then(|(p, n)| keys::describe(p, &n)) {
            Some(keys) => Drift::KeysChanged(path, keys),
            None => Drift::Modified(path),
        }
    }
}

#[cfg(test)]
mod tests;
