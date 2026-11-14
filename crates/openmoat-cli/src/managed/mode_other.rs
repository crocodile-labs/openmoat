//! A managed hook file written in place where there are no Unix modes
//! (Windows): the folder's inherited access list decides who reads it, as it
//! does for the host's own files there. Written to a temporary file and
//! renamed over it, so the host never reads half of one.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result};

/// Write `bytes` to `path`, creating its folders; an error where this
/// account may not.
pub(super) fn write_readable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let written = fs::write(&tmp, bytes)
        .with_context(|| format!("writing {}", tmp.display()))
        .and_then(|()| {
            fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
        });
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}
