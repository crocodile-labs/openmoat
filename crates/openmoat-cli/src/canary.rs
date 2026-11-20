//! Decoy keys (ADR-106): the fake credentials `openmoat init` plants when a
//! person says yes, the record of them in the state directory
//! (`canaries.json`, pinned by the lock and kept from the agent by
//! `kernel-self`), and what the guard and the proxy read from it.
//!
//! A decoy is planted only at a name no program loads on its own, beside the
//! real file attackers look for (`~/.npmrc.bak` beside `~/.npmrc`), and only
//! where nothing exists: never over a file, never into one. `openmoat
//! uninstall` deletes exactly the files the record lists, and only while each
//! still holds what was planted.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::canary::Decoys;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::home::Home;
use crate::integrity::sha256_hex;

mod decoys;
#[cfg(test)]
mod tests;

pub use decoys::{TARGETS, Target};

/// The record's file in the state directory.
pub const RECORD_FILE: &str = "canaries.json";

/// The record's format version.
const VERSION: u32 = 1;

/// Where the record of planted decoys is.
pub fn record_path(home: &Home) -> PathBuf {
    home.root().join(RECORD_FILE)
}

/// The decoys `openmoat init` planted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    #[serde(default)]
    pub decoys: Vec<Planted>,
}

/// One decoy file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Planted {
    /// The file, as the policy spells a path: `~/.npmrc.bak`.
    pub path: String,
    /// The SHA-256 of what was written, so uninstall deletes only that.
    pub sha256: String,
    /// The values the file holds, which no call may carry.
    pub values: Vec<String>,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            version: VERSION,
            decoys: Vec::new(),
        }
    }
}

impl Record {
    /// The record, from the bytes the lock check kept when it did (the
    /// guard); none planted when there is no file.
    pub fn load(home: &Home) -> Result<Self> {
        home.load_state(&record_path(home), Self::parse, |path| {
            if !path.exists() {
                return Ok(Self::default());
            }
            let text =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            Self::parse(&text, path)
        })
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let record: Self =
            serde_json::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
        if record.version != VERSION {
            bail!(
                "{} has version {}; this OpenMoat reads version {VERSION}",
                path.display(),
                record.version
            );
        }
        Ok(record)
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        let record = Self {
            version: VERSION,
            decoys: self.decoys.clone(),
        };
        let text = serde_json::to_string_pretty(&record)? + "\n";
        crate::home::write_private(&record_path(home), text.as_bytes())
    }

    /// What the guard checks calls against.
    pub fn decoys(&self) -> Decoys {
        Decoys {
            paths: self.decoys.iter().map(|d| d.path.clone()).collect(),
            values: self.decoys.iter().flat_map(|d| d.values.clone()).collect(),
        }
    }
}

/// The decoy values the proxy refuses to send anywhere.
pub fn values(home: &Home) -> Result<Vec<Zeroizing<String>>> {
    Ok(Record::load(home)?
        .decoys
        .into_iter()
        .flat_map(|d| d.values)
        .map(Zeroizing::new)
        .collect())
}

/// A decoy `init` can plant: its target and the file it would be.
#[derive(Debug, Clone)]
pub struct Offer {
    pub target: &'static Target,
    pub file: PathBuf,
}

/// The decoys that can be planted under `user` (the home directory): each
/// target whose folder exists and whose file does not, nothing there followed
/// or replaced; none already recorded.
pub fn offers(record: &Record, user: &Path) -> Vec<Offer> {
    TARGETS
        .iter()
        .filter(|t| !record.decoys.iter().any(|d| d.path == t.path))
        .filter_map(|target| {
            let file = target.file(user);
            let folder = file.parent()?;
            let free = fs::symlink_metadata(&file).is_err();
            (folder.is_dir() && free).then_some(Offer { target, file })
        })
        .collect()
}

/// Plant each of `offers` and record it. A file that appeared since the offer
/// was made is left alone (the file is created only when nothing is there).
/// The decoys planted.
pub fn plant(home: &Home, record: &mut Record, offers: &[Offer]) -> Result<Vec<PathBuf>> {
    let mut planted = Vec::new();
    for offer in offers {
        let values = offer.target.values()?;
        let text = offer.target.content(&values);
        if !create_new(&offer.file, text.as_bytes())? {
            continue;
        }
        record.decoys.push(Planted {
            path: offer.target.path.to_owned(),
            sha256: sha256_hex(text.as_bytes()),
            values,
        });
        planted.push(offer.file.clone());
    }
    record.save(home)?;
    Ok(planted)
}

/// What `openmoat uninstall` did with one decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    Deleted,
    /// It no longer holds what was planted: someone wrote to it, so it stays.
    Changed,
    /// Nothing is there any more.
    Gone,
}

/// Delete every recorded decoy under `user` that still holds what was
/// planted, then empty the record (kept, so the lock keeps pinning it).
pub fn remove(home: &Home, user: &Path) -> Result<Vec<(PathBuf, Removed)>> {
    let mut record = Record::load(home)?;
    if record.decoys.is_empty() {
        return Ok(Vec::new());
    }
    let mut done = Vec::new();
    for decoy in &record.decoys {
        let file = home_path(user, &decoy.path);
        let removed = match fs::symlink_metadata(&file) {
            Err(_) => Removed::Gone,
            Ok(meta) if !meta.is_file() => Removed::Changed,
            Ok(_) => {
                let bytes =
                    fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
                if sha256_hex(&bytes) == decoy.sha256 {
                    fs::remove_file(&file)
                        .with_context(|| format!("deleting {}", file.display()))?;
                    Removed::Deleted
                } else {
                    Removed::Changed
                }
            }
        };
        done.push((file, removed));
    }
    record.decoys.clear();
    record.save(home)?;
    Ok(done)
}

/// `path` (`~/…`) under `user`.
fn home_path(user: &Path, path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .map_or_else(|| PathBuf::from(path), |rest| user.join(rest))
}

/// Create `path` with `bytes`, owner-only, only when nothing is there: never
/// over a file or through a link. Whether it was created.
fn create_new(path: &Path, bytes: &[u8]) -> Result<bool> {
    use std::io::Write as _;
    let mut file = match crate::home::private_file_options().open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}
