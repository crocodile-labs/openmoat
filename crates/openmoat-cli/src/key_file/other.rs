//! Without Unix modes (Windows) the key file's access is the folder's ACL,
//! which OpenMoat does not read; only that it is a regular file is checked.

use std::fs::Metadata;
use std::path::Path;

use anyhow::{Result, bail};

pub(super) fn check(path: &Path, file: &Metadata, _: Option<&Metadata>) -> Result<()> {
    if !file.is_file() {
        bail!(
            "{} is not a regular file, so it is not used as a key",
            path.display()
        );
    }
    Ok(())
}
