//! Without Unix modes (Windows) the key file's access is the folder's ACL,
//! which OpenMoat does not read; only that it is a regular file is checked.

use std::fs::Metadata;
use std::path::Path;

use anyhow::{Result, bail};

pub(super) fn check(path: &Path, file: &Metadata, _: Option<&Metadata>, _: &str) -> Result<()> {
    if !file.is_file() {
        bail!(
            "{} is not a regular file, so it is not used as a key",
            path.display()
        );
    }
    Ok(())
}

/// Without Unix modes only that `dir` is a real folder is checked; its
/// access is its ACL, under the person's own temp directory.
pub(super) fn private_folder(dir: &Path, folder: &Metadata, _: &Metadata) -> Result<()> {
    if !folder.is_dir() || folder.file_type().is_symlink() {
        bail!("{} is not a folder", dir.display());
    }
    Ok(())
}
