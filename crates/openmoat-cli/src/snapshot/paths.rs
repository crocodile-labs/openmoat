//! Project-relative paths as a snapshot holds them, and writing them back
//! without following a link out of the project: relative to each folder,
//! held open, where the system has the calls for it (`unix.rs`), else
//! checking the folders again right before each change (`other.rs`).

use std::io;

// Built for the tests everywhere, so the checks Windows relies on run on
// every system.
#[cfg(any(not(unix), test))]
pub mod other;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
pub use other::{checked_target, put, remove};
#[cfg(unix)]
pub use unix::{checked_target, put, remove};

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

/// What to put at a path.
pub enum Content<'a> {
    File {
        bytes: &'a [u8],
        executable: bool,
    },
    /// A symbolic link; Windows needs a privilege for one, so there a
    /// restore names it as skipped.
    Link {
        target: &'a str,
    },
}

/// The fresh name a file is made under beside `name` before it is renamed
/// over it.
fn temp_name(name: &str) -> io::Result<String> {
    let suffix = crate::guard_relay::random_hex(6).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(format!(".{name}.openmoat-restore-{}", suffix.as_str()))
}
