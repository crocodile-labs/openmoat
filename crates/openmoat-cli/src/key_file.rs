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
    platform::check(path, &meta, dir.as_ref())?;
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
    platform::check(path, &meta, dir.as_ref())
        .err()
        .map(|e| format!("{e:#}"))
}
