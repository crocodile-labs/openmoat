//! The one change sandboxed start makes outside OpenMoat's directory (ADR-106
//! §2): two lines at the end of the person's shell start-up file that put the
//! shim directory first on `PATH`, written only after the person saw them and
//! said yes, with the file backed up first. The default policy's `shell-rc`
//! rule keeps an agent from writing this file; `init`, run by the person, may.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::home::{Home, KeepMode, write_like};
use crate::install::{HOOK_BACKUP, back_up, backup_path};

/// The first of the two lines, which marks them as OpenMoat's.
pub const MARK: &str =
    "# Added by `openmoat init` (sandboxed start); `openmoat uninstall` removes these two lines.";

/// The start-up file `init` wrote the lines to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Written {
    pub path: PathBuf,
    /// Whether `init` created the file.
    #[serde(default)]
    pub created: bool,
    /// The lines as written, which uninstall takes out.
    pub lines: String,
}

/// The start-up file of the person's shell `shell` (`$SHELL`) under `user`:
/// zsh's `~/.zshrc`; bash's `~/.bash_profile` on macOS, whose terminals start
/// login shells, `~/.bashrc` elsewhere. `None` for another shell, whose line
/// `init` shows for the person to add.
pub fn file(user: &Path, shell: Option<&str>) -> Option<PathBuf> {
    let name = Path::new(shell?).file_name()?.to_str()?;
    match name {
        "zsh" => Some(user.join(".zshrc")),
        "bash" if cfg!(target_os = "macos") => Some(user.join(".bash_profile")),
        "bash" => Some(user.join(".bashrc")),
        _ => None,
    }
}

/// The two lines for the shim directory `dir`, `$HOME`-relative where it is
/// below `user`.
pub fn lines(dir: &Path, user: &Path) -> String {
    let shown = match dir.strip_prefix(user).ok().and_then(Path::to_str) {
        Some(rest) => format!("$HOME/{}", escape(rest)),
        None => escape(&dir.display().to_string()),
    };
    format!("{MARK}\nexport PATH=\"{shown}:$PATH\"\n")
}

/// `text` safe inside double quotes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The diff `d` shows: the lines added at the end of `path`.
pub fn diff(path: &Path, lines: &str) -> String {
    let verb = if path.exists() { "" } else { " (new file)" };
    let mut out = format!("--- {}{verb}\n", path.display());
    for line in lines.lines() {
        out.push_str("+ ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Add `lines` at the end of `path`, backed up first; `None` when they are
/// there already.
pub fn add(home: &Home, path: &Path, lines: &str) -> Result<Option<Written>> {
    let created = !path.exists();
    let before = if created {
        String::new()
    } else {
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    };
    if before.contains(lines) {
        return Ok(None);
    }
    back_up(home, path, HOOK_BACKUP)?;
    let mut after = before;
    if !after.is_empty() && !after.ends_with('\n') {
        after.push('\n');
    }
    after.push_str(lines);
    write_like(path, after.as_bytes(), path, KeepMode::All)?;
    Ok(Some(Written {
        path: path.to_path_buf(),
        created,
        lines: lines.to_owned(),
    }))
}

/// What `openmoat uninstall` did with the start-up file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undone {
    /// Back as it was, from the backup.
    Restored(PathBuf, PathBuf),
    /// `init` created it and nothing else is in it.
    Deleted(PathBuf),
    /// The lines taken out, the person's later changes kept.
    Stripped(PathBuf),
    /// The lines are no longer there.
    Absent(PathBuf),
}

impl std::fmt::Display for Undone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Restored(path, backup) => {
                write!(f, "{} restored from {}", path.display(), backup.display())
            }
            Self::Deleted(path) => {
                write!(f, "{} deleted (openmoat init created it)", path.display())
            }
            Self::Stripped(path) => write!(
                f,
                "{}: OpenMoat's two lines removed, your changes kept",
                path.display()
            ),
            Self::Absent(path) => write!(f, "{}: OpenMoat's lines were not there", path.display()),
        }
    }
}

/// Take the lines `written` records out of its file.
pub fn remove(written: &Written) -> Result<Undone> {
    let path = &written.path;
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(Undone::Absent(path.clone()));
    };
    let ours = written.lines.as_str();
    let Some(at) = text.find(ours).filter(|_| ours.starts_with(MARK)) else {
        return Ok(Undone::Absent(path.clone()));
    };
    let stripped = format!("{}{}", &text[..at], &text[at + ours.len()..]);
    let backup = backup_path(path, HOOK_BACKUP);
    let original = fs::read(&backup).ok();
    let matches_backup = |left: &str| {
        original
            .as_deref()
            .is_some_and(|b| b == left.as_bytes() || b == left.trim_end_matches('\n').as_bytes())
    };
    if matches_backup(&stripped) {
        let bytes = original.unwrap_or_default();
        write_like(path, &bytes, &backup, KeepMode::All)?;
        fs::remove_file(&backup).with_context(|| format!("deleting {}", backup.display()))?;
        return Ok(Undone::Restored(path.clone(), backup));
    }
    if written.created && stripped.trim().is_empty() {
        fs::remove_file(path).with_context(|| format!("deleting {}", path.display()))?;
        return Ok(Undone::Deleted(path.clone()));
    }
    write_like(path, stripped.as_bytes(), path, KeepMode::All)?;
    Ok(Undone::Stripped(path.clone()))
}
