//! Project-relative paths as a snapshot holds them, and writing them back
//! without following a link out of the project.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Whether `rel`, a path git listed, is a plain relative path inside the
/// project: no empty, `.` or `..` component, not absolute, no backslash
/// (a separator on Windows). git checks this for its own trees; a restore
/// checks it again before writing.
pub fn is_plain(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel.contains('\\')
        && !rel.contains('\0')
        && rel
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Whether `rel` lies inside a `.git` or `.moat` folder at any depth, in any
/// letter case (macOS and Windows file systems ignore it).
pub fn in_state_folder(rel: &str) -> bool {
    rel.split('/')
        .any(|part| part.eq_ignore_ascii_case(".git") || part.eq_ignore_ascii_case(".moat"))
}

/// Why a path cannot be written back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// A folder on its path is a symbolic link now, or a file.
    Parent(String),
    /// The path is a folder now.
    Folder,
    /// The name is not a plain relative path inside the project.
    Name,
}

impl Blocked {
    pub fn words(&self) -> String {
        match self {
            Self::Parent(part) => {
                format!(
                    "`{part}` on its path is a link or a file now, so nothing is written through it"
                )
            }
            Self::Folder => "it is a folder now".to_owned(),
            Self::Name => "its name is not a plain path inside the project".to_owned(),
        }
    }
}

/// The absolute path of `rel` in `root` once every folder above it is a real
/// folder (missing ones are created when `create`), never a link: a link an
/// agent left there could point anywhere, `~/.ssh` included.
pub fn checked_target(root: &Path, rel: &str, create: bool) -> Result<PathBuf, Blocked> {
    if !is_plain(rel) || in_state_folder(rel) {
        return Err(Blocked::Name);
    }
    let parts: Vec<&str> = rel.split('/').collect();
    let mut at = root.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        at.push(part);
        if i + 1 == parts.len() {
            break;
        }
        let shown = || parts[..=i].join("/");
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
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

/// What to put at a path.
pub enum Content<'a> {
    File { bytes: &'a [u8], executable: bool },
    Link { target: &'a str },
}

/// Put `content` at `path` (whose folders [`checked_target`] checked): made
/// beside it under a fresh name, then renamed over it, which replaces a link
/// there instead of writing through it.
pub fn put(path: &Path, content: &Content<'_>) -> io::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let suffix = crate::guard_relay::random_hex(6).map_err(|e| io::Error::other(e.to_string()))?;
    let temp = path.with_file_name(format!(".{name}.openmoat-restore-{}", suffix.as_str()));
    let made = match content {
        Content::File { bytes, executable } => write_new(&temp, bytes, *executable),
        Content::Link { target } => link(target, &temp),
    };
    made.and_then(|()| fs::rename(&temp, path))
        .inspect_err(|_| {
            let _ = fs::remove_file(&temp);
        })
}

fn write_new(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, if executable { 0o755 } else { 0o644 });
    #[cfg(not(unix))]
    let _ = executable;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn link(target: &str, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

/// Windows needs a privilege for symbolic links; a restore names what it skipped.
#[cfg(not(unix))]
fn link(_target: &str, _at: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are not restored on this system",
    ))
}

/// Remove the file or link at `path`, never what a link points at.
pub fn remove(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}
