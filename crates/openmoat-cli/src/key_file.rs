//! Reading a private key from OpenMoat's state directory: the proxy session
//! key (`proxy.key`, ADR-044) and the proxy CA's key (`proxy-ca/ca.key`,
//! ADR-043).
//!
//! OpenMoat writes both owner-only, in owner-only directories. A key that has
//! become readable by others since (a backup restored with other modes, a
//! state directory on a shared disk) may already be in another user's hands,
//! who could then sign session credentials or certificates. Such a key is
//! refused, not used, and the error names the file and the fix. On Unix the
//! mode is read from the opened file, so the bytes checked are the bytes read;
//! where there are no Unix modes (Windows) nothing is checked here.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

#[cfg(not(unix))]
mod other;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
use other as platform;
#[cfg(unix)]
use unix as platform;

/// Whether `dir` is a folder of this user's that no one else may enter:
/// owned by the owner of `mine` (a file this process just made in it) and
/// with no group or other bits. A folder planted in a shared temp directory
/// before OpenMoat made it fails this (ADR-062's session trust files).
pub fn private_folder(dir: &Path, mine: &Path) -> Result<()> {
    let folder =
        std::fs::symlink_metadata(dir).with_context(|| format!("reading {}", dir.display()))?;
    let made =
        std::fs::symlink_metadata(mine).with_context(|| format!("reading {}", mine.display()))?;
    platform::private_folder(dir, &folder, &made)
}

/// The key in `path`, refused when the file is not a regular file, or when it
/// or its directory is open to others ([`platform::check`]).
pub fn read(path: &Path) -> Result<Zeroizing<String>> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?;
    let dir = path
        .parent()
        .map(std::fs::metadata)
        .transpose()
        .with_context(|| format!("reading the folder of {}", path.display()))?;
    platform::check(path, &meta, dir.as_ref(), remake(path))?;
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(text)
}

/// Each key file's mode, for `openmoat doctor`: `None` when the file is
/// missing or its mode is fine, else what is wrong with it.
pub fn problem(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let dir = path.parent().and_then(|d| std::fs::metadata(d).ok());
    platform::check(path, &meta, dir.as_ref(), remake(path))
        .err()
        .map(|e| format!("{e:#}"))
}

/// How to replace a key that may be known. The audit key is never removed
/// alone: the events it keyed would no longer verify, and no writer makes a
/// new one over them (ADR-101).
fn remake(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|n| n.to_str());
    if name == Some(crate::audit_key::KEY_FILE) {
        "move the audit log aside as evidence and run `openmoat init`, which starts a new log \
         with a new key (never remove the key alone)"
    } else if name == Some(crate::audit_signing::KEY_FILE) {
        "run `openmoat audit checkpoint --new-key` in your terminal, and give the new public key \
         `openmoat doctor` shows to whoever checks your checkpoints"
    } else {
        "make a new one (remove the file; `openmoat proxy ca init` for the CA)"
    }
}
