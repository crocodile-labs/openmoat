//! Unix: the key file must be a regular file nobody else may read or write
//! (no bit of `0o077`), in a directory nobody else may write (no bit of
//! `0o022`), so no other user can read it or put another key in its place. A
//! directory others may only list and enter keeps an owner-only file private.

use std::fs::Metadata;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Result, bail};

/// Group and other bits of a key file.
const FILE_OPEN: u32 = 0o077;
/// Group and other write bits of its directory.
const DIR_WRITABLE: u32 = 0o022;

pub(super) fn check(path: &Path, file: &Metadata, dir: Option<&Metadata>) -> Result<()> {
    if !file.is_file() {
        bail!(
            "{} is not a regular file, so it is not used as a key",
            path.display()
        );
    }
    let mode = file.permissions().mode() & 0o777;
    if mode & FILE_OPEN != 0 {
        bail!(
            "{} has mode {mode:03o}: other users may read this key, so it is not used. It may \
             already be known: make a new one (remove the file; `openmoat proxy ca init` for the \
             CA), or, if nobody else could read it, `chmod 600` it",
            path.display()
        );
    }
    if let Some(dir) = dir {
        let mode = dir.permissions().mode() & 0o777;
        if mode & DIR_WRITABLE != 0 {
            let folder = path.parent().unwrap_or(path);
            bail!(
                "{} has mode {mode:03o}: other users may replace the key {} in it, so it is not \
                 used; `chmod 700` the folder",
                folder.display(),
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::super::read;

    fn key_in(dir: &std::path::Path, mode: u32) -> std::path::PathBuf {
        let path = dir.join("proxy.key");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "k\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn an_owner_only_key_is_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(read(&key_in(dir.path(), 0o600)).unwrap().as_str(), "k\n");
        assert_eq!(read(&key_in(dir.path(), 0o400)).unwrap().as_str(), "k\n");
        // A folder others may list keeps an owner-only key private.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read(&key_in(dir.path(), 0o600)).is_ok());
    }

    #[test]
    fn a_key_others_may_read_or_replace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660, 0o666] {
            let error = read(&key_in(dir.path(), mode)).unwrap_err();
            assert!(
                format!("{error:#}").contains(&format!("mode {mode:03o}")),
                "{error:#}"
            );
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = read(&key_in(dir.path(), 0o600)).unwrap_err();
        assert!(format!("{error:#}").contains("may replace"), "{error:#}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_directory_is_not_a_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let sub = dir.path().join("proxy.key");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read(&sub).is_err());
    }
}
