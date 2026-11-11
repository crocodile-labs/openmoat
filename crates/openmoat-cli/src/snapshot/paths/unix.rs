//! Writing a path back relative to its folder, held open: each folder from
//! the project down is opened with `O_NOFOLLOW`, so none of them is a link,
//! and every later step (the temporary file, the rename, the delete) is made
//! in the folder that was opened, whatever is put at its name meanwhile.
//! A process of the agent still running cannot turn a checked folder into a
//! link out of the project between the check and the write (ADR-085 §4).

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use super::{Blocked, Content, in_state_folder, is_plain, temp_name};

/// A path to write back: its folder, open, and its name in it.
#[derive(Debug)]
pub struct Target {
    folder: OwnedFd,
    name: String,
}

/// The folder of `rel` in `root`, opened through real folders only (missing
/// ones are created when `create`), never a link: a link an agent left there
/// could point anywhere, `~/.ssh` included. `rel` itself may not be a folder.
pub fn checked_target(root: &Path, rel: &str, create: bool) -> Result<Target, Blocked> {
    if !is_plain(rel) || in_state_folder(rel) {
        return Err(Blocked::Name);
    }
    let parts: Vec<&str> = rel.split('/').collect();
    let Some((name, folders)) = parts.split_last() else {
        return Err(Blocked::Name);
    };
    let shown = |i: usize| parts[..=i].join("/");
    let mut folder = rustix::fs::open(root, folder_flags(false), Mode::empty())
        .map_err(|_| Blocked::Parent(".".to_owned()))?;
    for (i, part) in folders.iter().enumerate() {
        folder = match rustix::fs::openat(&folder, *part, folder_flags(true), Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) if create => {
                rustix::fs::mkdirat(&folder, *part, Mode::from_bits_truncate(0o755))
                    .map_err(|_| Blocked::Parent(shown(i)))?;
                rustix::fs::openat(&folder, *part, folder_flags(true), Mode::empty())
                    .map_err(|_| Blocked::Parent(shown(i)))?
            }
            Err(_) => return Err(Blocked::Parent(shown(i))),
        };
    }
    if is_folder(&folder, name) {
        return Err(Blocked::Folder);
    }
    Ok(Target {
        folder,
        name: (*name).to_owned(),
    })
}

/// A folder, opened to work in; `nofollow` refuses a link at its name.
fn folder_flags(nofollow: bool) -> OFlags {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    if nofollow {
        flags | OFlags::NOFOLLOW
    } else {
        flags
    }
}

fn is_folder(folder: &OwnedFd, name: &str) -> bool {
    rustix::fs::statat(folder, name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory)
}

/// Put `content` at `target`: made in its folder under a fresh name, then
/// renamed over it, which replaces a link there instead of writing through it.
pub fn put(target: &Target, content: &Content<'_>) -> io::Result<()> {
    let temp = temp_name(&target.name)?;
    let made = match content {
        Content::File { bytes, executable } => write_new(target, &temp, bytes, *executable),
        Content::Link { target: to } => {
            rustix::fs::symlinkat(*to, &target.folder, temp.as_str()).map_err(io::Error::from)
        }
    };
    made.and_then(|()| {
        if is_folder(&target.folder, &target.name) {
            return Err(io::Error::other("it is a folder now"));
        }
        rustix::fs::renameat(
            &target.folder,
            temp.as_str(),
            &target.folder,
            target.name.as_str(),
        )
        .map_err(io::Error::from)
    })
    .inspect_err(|_| {
        let _ = rustix::fs::unlinkat(&target.folder, temp.as_str(), AtFlags::empty());
    })
}

fn write_new(target: &Target, temp: &str, bytes: &[u8], executable: bool) -> io::Result<()> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mode = Mode::from_bits_truncate(if executable { 0o755 } else { 0o644 });
    let mut file = File::from(rustix::fs::openat(&target.folder, temp, flags, mode)?);
    file.write_all(bytes)?;
    file.sync_all()
}

/// Remove the file or link at `target`, never what a link points at.
pub fn remove(target: &Target) -> io::Result<()> {
    rustix::fs::unlinkat(&target.folder, target.name.as_str(), AtFlags::empty())
        .map_err(io::Error::from)
}
