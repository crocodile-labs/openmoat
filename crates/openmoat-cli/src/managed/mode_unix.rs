//! A managed hook file written in place on Unix: `0644` in folders `0755`
//! (as the system's umask leaves them), since the host reads it for every
//! account of the machine; written to a temporary file and renamed over it,
//! so the host never reads half of one.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context as _, Result};

/// The mode of the file.
const FILE_MODE: u32 = 0o644;

/// Write `bytes` to `path`, readable by every account, creating its folders
/// as the system creates them; an error where this account may not.
pub(super) fn write_readable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A hidden name: hosts that merge a folder skip hidden files.
    let tmp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
        // The umask may have taken bits the host's other accounts need.
        fs::set_permissions(&tmp, fs::Permissions::from_mode(FILE_MODE))
            .with_context(|| format!("setting the mode of {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}
