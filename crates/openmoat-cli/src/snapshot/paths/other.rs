//! Writing a path back where the standard library offers no folder-relative
//! calls (Windows): every folder above it is checked to be a real folder
//! (a junction or a link is not), and checked again, with the folder's
//! resolved place, right before the rename or the delete; any change refuses.
//! What is left is the moment between that check and the call (ADR-085 §4).

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::{Blocked, Content, in_state_folder, is_plain, temp_name};

/// A path to write back, and where its folder resolved when it was checked.
#[derive(Debug)]
pub struct Target {
    root: PathBuf,
    rel: String,
    path: PathBuf,
    folder: PathBuf,
}

/// The absolute path of `rel` in `root` once every folder above it is a real
/// folder (missing ones are created when `create`), never a link: a link an
/// agent left there could point anywhere, `~/.ssh` included.
pub fn checked_target(root: &Path, rel: &str, create: bool) -> Result<Target, Blocked> {
    if !is_plain(rel) || in_state_folder(rel) {
        return Err(Blocked::Name);
    }
    let path = walk(root, rel, create)?;
    let folder = path
        .parent()
        .and_then(|p| fs::canonicalize(p).ok())
        .ok_or_else(|| Blocked::Parent(".".to_owned()))?;
    Ok(Target {
        root: root.to_path_buf(),
        rel: rel.to_owned(),
        path,
        folder,
    })
}

fn walk(root: &Path, rel: &str, create: bool) -> Result<PathBuf, Blocked> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut at = root.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        at.push(part);
        if i + 1 == parts.len() {
            break;
        }
        let shown = || parts[..=i].join("/");
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                fs::create_dir(&at).map_err(|_| Blocked::Parent(shown()))?;
            }
            _ => return Err(Blocked::Parent(shown())),
        }
    }
    if fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
        return Err(Blocked::Folder);
    }
    Ok(at)
}

/// The folders are still the ones checked: real folders resolving where
/// they did.
fn unchanged(target: &Target) -> io::Result<()> {
    let again = walk(&target.root, &target.rel, false)
        .ok()
        .and_then(|path| path.parent().and_then(|p| fs::canonicalize(p).ok()));
    if again.as_deref() == Some(target.folder.as_path()) {
        Ok(())
    } else {
        Err(io::Error::other(
            "a folder on its path changed during the restore, so nothing is written through it",
        ))
    }
}

/// Put `content` at `target`: made beside it under a fresh name, then, once
/// its folders are checked again, renamed over it.
pub fn put(target: &Target, content: &Content<'_>) -> io::Result<()> {
    let temp = target.path.with_file_name(temp_name(&name(target))?);
    let made = match content {
        Content::File { bytes, executable } => write_new(&temp, bytes, *executable),
        Content::Link { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "symbolic links are not restored on this system",
        )),
    };
    made.and_then(|()| unchanged(target))
        .and_then(|()| fs::rename(&temp, &target.path))
        .inspect_err(|_| {
            let _ = fs::remove_file(&temp);
        })
}

fn name(target: &Target) -> String {
    target
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn write_new(path: &Path, bytes: &[u8], _executable: bool) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Remove the file or link at `target`, never what a link points at, once
/// its folders are checked again.
pub fn remove(target: &Target) -> io::Result<()> {
    unchanged(target)?;
    fs::remove_file(&target.path)
}
