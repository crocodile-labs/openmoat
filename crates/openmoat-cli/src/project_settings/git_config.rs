//! A repository's own git configuration (`.git/config`, `config.worktree`)
//! can name programs git runs: `core.fsmonitor` on every `git status`, a
//! hooks folder, a pager or editor, a diff or merge driver, a filter, a
//! credential helper, an alias starting with `!`, another file to include.
//! The agent's own background git runs them when a session starts, before any
//! hook and outside any sandbox but `openmoat run`'s, and a repository that
//! arrives as files (an archive, a shared drive) keeps its `.git` as it was
//! made. No hook can stop that, so `moat doctor` and `moat status` name each
//! such key. The files are read as text: running git to read them would run
//! the very programs they name.

use std::fs;
use std::path::{Path, PathBuf};

/// A configuration file larger than this is named unread rather than parsed.
const MAX_BYTES: u64 = 1024 * 1024;

/// The hooks folders a repository's `core.hooksPath` usually names, whose
/// files `runs-later` already holds for review (husky sets `.husky/_`).
const KNOWN_HOOK_DIRS: &[&str] = &[
    ".husky",
    ".husky/_",
    ".githooks",
    ".git-hooks",
    "githooks",
    "git-hooks",
    "scripts/git-hooks",
];

/// The filter commands `git lfs install --local` writes.
const LFS_FILTERS: &[&str] = &[
    "git-lfs clean -- %f",
    "git-lfs smudge -- %f",
    "git-lfs filter-process",
];

/// One line per configuration file of the repository `cwd` is in that sets a
/// key making git run a program: the file and its keys, in file order.
#[must_use]
pub fn warnings(cwd: &Path, user_home: &Path) -> Vec<String> {
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut lines = Vec::new();
    for root in super::project_dirs(cwd, user_home) {
        for file in config_files(&root) {
            if seen.contains(&file) {
                continue;
            }
            match read(&file) {
                Read::TooLarge => lines.push(format!(
                    "{}: larger than {MAX_BYTES} bytes, not read; git reads it and may run \
                     what it names, so review it",
                    file.display()
                )),
                Read::Text(text) => {
                    let keys = program_keys(&text);
                    if !keys.is_empty() {
                        lines.push(format!(
                            "{}: sets {}, which git runs as a program, the agent's own \
                             background git included, when a session starts and before any \
                             hook; review it and remove what you did not add",
                            file.display(),
                            keys.join(", ")
                        ));
                    }
                }
                Read::Missing => {}
            }
            seen.push(file);
        }
    }
    lines
}

/// [`warnings`] for the current directory, for `moat doctor` and `moat
/// status`; empty when it or the home directory cannot be found.
#[must_use]
pub fn warnings_here() -> Vec<String> {
    let (Ok(cwd), Ok(user_home)) = (std::env::current_dir(), crate::home::user_home()) else {
        return Vec::new();
    };
    warnings(&cwd, &user_home)
}

/// The configuration files git reads for the repository at `root`: those in
/// its `.git` directory, or in the directory a `.git` file names (a linked
/// worktree or a submodule), with the main repository's for a worktree.
fn config_files(root: &Path) -> Vec<PathBuf> {
    let dot_git = root.join(".git");
    let mut dirs = Vec::new();
    if dot_git.is_dir() {
        dirs.push(dot_git);
    } else if let Some(dir) = gitdir_of(&dot_git) {
        if let Some(common) = common_dir(&dir) {
            dirs.push(common);
        }
        dirs.push(dir);
    }
    dirs.iter()
        .flat_map(|dir| [dir.join("config"), dir.join("config.worktree")])
        .filter(|path| path.is_file())
        .collect()
}

/// The directory a `.git` file's `gitdir: <path>` line names, taken from the
/// file's own directory when relative.
fn gitdir_of(file: &Path) -> Option<PathBuf> {
    let Read::Text(text) = read(file) else {
        return None;
    };
    let named = text.lines().find_map(|line| line.strip_prefix("gitdir:"))?;
    Some(file.parent()?.join(named.trim()))
}

/// The main repository's `.git` a linked worktree's `commondir` file names.
fn common_dir(dir: &Path) -> Option<PathBuf> {
    let Read::Text(text) = read(&dir.join("commondir")) else {
        return None;
    };
    Some(dir.join(text.trim()))
}

/// A file's text, read as git does whatever its encoding.
#[derive(Debug)]
enum Read {
    Missing,
    TooLarge,
    Text(String),
}

fn read(path: &Path) -> Read {
    let Ok(meta) = fs::metadata(path) else {
        return Read::Missing;
    };
    if !meta.is_file() {
        return Read::Missing;
    }
    if meta.len() > MAX_BYTES {
        return Read::TooLarge;
    }
    fs::read(path).map_or(Read::Missing, |bytes| {
        Read::Text(String::from_utf8_lossy(&bytes).into_owned())
    })
}

/// The keys of git configuration `text` that make git run a program, as
/// `section.key` or `section.subsection.key`, each once, in file order.
fn program_keys(text: &str) -> Vec<String> {
    let mut section = String::new();
    let mut subsection: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut rest = line.trim();
        if let Some(header) = rest.strip_prefix('[') {
            let Some(end) = header.find(']') else {
                continue;
            };
            (section, subsection) = parse_header(&header[..end]);
            rest = header[end + 1..].trim();
        }
        if rest.is_empty() || rest.starts_with('#') || rest.starts_with(';') {
            continue;
        }
        // A key without `=` is a boolean set to true.
        let (name, value) = rest.split_once('=').unwrap_or((rest, "true"));
        let name = name.trim().to_ascii_lowercase();
        if runs_program(&section, subsection.as_deref(), &name, &value_of(value)) {
            let key = match &subsection {
                Some(sub) => format!("{section}.{sub}.{name}"),
                None => format!("{section}.{name}"),
            };
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// `section "subsection"`, or the older `section.subsection`; the section is
/// compared without case, as git does, and so is an old-style subsection.
fn parse_header(header: &str) -> (String, Option<String>) {
    let header = header.trim();
    if let Some((section, quoted)) = header.split_once(char::is_whitespace) {
        let sub = quoted.trim().trim_matches('"').replace("\\\"", "\"");
        return (section.to_ascii_lowercase(), Some(sub));
    }
    match header.split_once('.') {
        Some((section, sub)) => (section.to_ascii_lowercase(), Some(sub.to_ascii_lowercase())),
        None => (header.to_ascii_lowercase(), None),
    }
}

/// A value without its quotes, or up to a `#` or `;` comment when unquoted.
fn value_of(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(quoted) = raw.strip_prefix('"') {
        return quoted.split('"').next().unwrap_or_default().to_owned();
    }
    raw.split(['#', ';'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Whether git runs `value` as a program for this key.
fn runs_program(section: &str, subsection: Option<&str>, name: &str, value: &str) -> bool {
    let set = !value.is_empty();
    match (section, subsection, name) {
        // `core.fsmonitor = true` starts git's own daemon and a `pager.<command>`
        // boolean turns paging on or off; any other value is a program
        ("core", None, "fsmonitor") | ("pager", None, _) => set && !is_bool(value),
        ("core", None, "hookspath") => {
            set && !KNOWN_HOOK_DIRS.contains(&value.trim_end_matches('/'))
        }
        ("core", None, "pager" | "editor" | "sshcommand" | "gitproxy" | "askpass")
        | ("sequence", None, "editor")
        | ("diff", None, "external")
        | ("diff", Some(_), "command" | "textconv")
        | ("merge", Some(_), "driver")
        | ("gpg", _, "program")
        | ("include", None, "path")
        | ("includeif", Some(_), "path")
        | ("remote", Some(_), "uploadpack" | "receivepack")
        | ("uploadpack", None, "packobjectshook") => set,
        ("filter", Some(_), "clean" | "smudge" | "process") => set && !LFS_FILTERS.contains(&value),
        ("credential", _, "helper") => {
            value.starts_with('!') || value.contains('/') || value.contains('\\')
        }
        ("alias", _, _) => value.starts_with('!'),
        _ => false,
    }
}

/// A git boolean (`true`, `no`, `on`, `0`, …).
fn is_bool(value: &str) -> bool {
    ["true", "false", "yes", "no", "on", "off", "1", "0"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
}

#[cfg(test)]
mod tests;
