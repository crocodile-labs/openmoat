//! The guard checks its own binary against the lock (ADR-071).
//!
//! Every re-pin records the SHA-256 of the binary the hooks run
//! ([`super::Lock::binary`]) and the release it reports. Each call, the guard
//! compares the file it runs from with that record, where it runs the very
//! file the lock names (the stable path, not a versioned file a package
//! manager left behind).
//!
//! - Same release, other bytes: the file was changed in place (patched,
//!   truncated, replaced by another build of the same version). The guard
//!   denies every call (`kernel-integrity`) until a person runs `openmoat init`.
//! - Another release: the person upgraded. The hooks keep working, as an
//!   upgrade in place always did (ADR-016), and `openmoat status` and `openmoat
//!   doctor` say to run `openmoat init` so the new binary is recorded.
//!
//! Hashing the binary takes tens of milliseconds, so the digest is kept in
//! [`CACHE_FILE`] beside the lock, keyed by the file's size, modification time
//! and (on Unix) device and inode, and computed again only when one of those
//! changes. What this cannot do: a binary changed to skip the check skips it.
//! It catches a file changed in place by something other than a release.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::home::Home;

/// The digest cache's name in the state directory; not pinned: it only saves
/// the guard hashing its binary again.
pub const CACHE_FILE: &str = "binary-hash.json";

/// The release this binary reports, as the lock records it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How the running binary compares with the lock's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfCheck {
    /// The bytes the lock recorded.
    Same,
    /// The lock records no digest (written before ADR-071).
    NotRecorded,
    /// This process does not run the file the lock names; the hooks' own
    /// path checks report that.
    OtherFile,
    /// Another release than the lock recorded: an upgrade in place.
    Upgraded {
        /// The release the lock recorded.
        recorded: String,
    },
    /// The same release with other bytes: the file was changed in place.
    Changed {
        /// The binary's path.
        path: PathBuf,
    },
    /// The binary it runs could not be read to hash; the guard denies.
    Unreadable(String),
}

impl SelfCheck {
    /// The reason a call is denied for this, if it is.
    pub fn deny_reason(&self) -> Option<String> {
        match self {
            Self::Changed { path } => Some(format!(
                "the openmoat binary {} changed since the lock recorded it, though it reports \
                 the same release ({VERSION}): run `openmoat init` from your own terminal if you \
                 rebuilt or reinstalled it yourself",
                path.display()
            )),
            Self::Unreadable(why) => Some(format!(
                "the openmoat binary could not be checked against the lock: {why}"
            )),
            Self::Same | Self::NotRecorded | Self::OtherFile | Self::Upgraded { .. } => None,
        }
    }

    /// What `status` and `doctor` say about it, if anything.
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Upgraded { recorded } => Some(format!(
                "binary is release {VERSION}, the lock recorded {recorded}; run `openmoat init` \
                 to record it"
            )),
            Self::NotRecorded => Some(
                "the lock records no digest of the binary (written by an older OpenMoat); run \
                 `openmoat init`"
                    .to_owned(),
            ),
            Self::Changed { .. } | Self::Unreadable(_) => self.deny_reason(),
            Self::Same | Self::OtherFile => None,
        }
    }
}

/// The record a re-pin keeps of `binary`: its digest (through `home`'s
/// cache) and this release, or `None` when it cannot be read.
pub fn record(home: &Home, binary: &Path) -> Option<(String, String)> {
    let file = fs::canonicalize(binary).ok()?;
    let digest = cached_digest(&home.root().join(CACHE_FILE), &file).ok()?;
    Some((digest, VERSION.to_owned()))
}

/// How the running binary compares with what `lock` recorded, with the cache
/// in `home`.
pub fn check(home: &Home, lock: &super::Lock) -> SelfCheck {
    let (Some(recorded), Some(version)) = (&lock.binary_sha256, &lock.binary_version) else {
        return SelfCheck::NotRecorded;
    };
    // A running file that no longer resolves was replaced while it started
    // (an upgrade in progress); the next call runs the new one.
    let Ok(exe) = std::env::current_exe().and_then(fs::canonicalize) else {
        return SelfCheck::OtherFile;
    };
    // The lock's path resolves to another file: a versioned path a package
    // manager is replacing, or a copy; not this check's to judge.
    if fs::canonicalize(&lock.binary).ok().as_ref() != Some(&exe) {
        return SelfCheck::OtherFile;
    }
    if version != VERSION {
        return SelfCheck::Upgraded {
            recorded: version.clone(),
        };
    }
    match cached_digest(&home.root().join(CACHE_FILE), &exe) {
        Ok(digest) if digest == *recorded => SelfCheck::Same,
        Ok(_) => SelfCheck::Changed { path: exe },
        Err(error) => SelfCheck::Unreadable(format!("{error:#}")),
    }
}

/// What the cache keeps: the file it hashed, how it looked, and its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Cached {
    path: String,
    stamp: Stamp,
    sha256: String,
}

/// What identifies one version of a file without reading it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    len: u64,
    modified_ns: u128,
    /// Device and inode on Unix; `(0, 0)` elsewhere.
    id: (u64, u64),
}

impl Stamp {
    fn of(meta: &fs::Metadata) -> Self {
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        Self {
            len: meta.len(),
            modified_ns,
            id: file_id(meta),
        }
    }
}

#[cfg(unix)]
fn file_id(meta: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn file_id(_: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// `exe`'s digest: the cached one while the file looks as it did when it was
/// hashed, else hashed again and the cache rewritten (best effort: a guard
/// that cannot write it only hashes again next time).
fn cached_digest(cache: &Path, exe: &Path) -> Result<String> {
    let stamp =
        Stamp::of(&fs::metadata(exe).with_context(|| format!("reading {}", exe.display()))?);
    let path = exe.to_string_lossy().into_owned();
    let kept = fs::read(cache)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Cached>(&bytes).ok())
        .filter(|c| c.path == path && c.stamp == stamp);
    if let Some(kept) = kept {
        return Ok(kept.sha256);
    }
    let sha256 = sha256_file(exe)?;
    let fresh = Cached {
        path,
        stamp,
        sha256: sha256.clone(),
    };
    if let Ok(text) = serde_json::to_vec(&fresh) {
        let _ = crate::home::write_private(cache, &text);
    }
    Ok(sha256)
}

/// The lowercase hex SHA-256 of the file at `path`, read in pieces.
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests;
