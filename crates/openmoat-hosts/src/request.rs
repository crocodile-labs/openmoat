//! Where a call is decided from, and where it runs.
//!
//! The project (`${project}`) is the session's: the directory the person
//! started the agent in. Some hosts send the directory the tool runs in instead
//! (Codex sends a shell call's `workdir`, Cursor the terminal's directory),
//! which the model chooses. A model-chosen directory never decides which
//! directory is the project: such a request is decided from the session's
//! directory, and its action says where the tool runs, a shell command after a
//! `cd` there and every relative path taken from it, as Gemini CLI's
//! `dir_path` is ([`HookRequest::from_session_dir`]).

use openmoat_core::Action;

use crate::HookRequest;

/// Why a search that names no directory is not all checked: the host then
/// searches every directory of its workspace, and the hook payload names only
/// the working directory. Gemini CLI does so (`workspaceContext.getDirectories()`
/// in `packages/core/src/tools/grep.ts`, `glob.ts` and `read-many-files.ts`,
/// 0.65.0); the guard replaces the mark with the directories the host's
/// settings add ([`HookRequest::with_workspace_dirs`]).
pub(crate) const EVERY_WORKSPACE_DIRECTORY: &str = "without a `dir_path` Gemini CLI searches \
     every workspace directory, and the hook names only the working directory";

/// Paths are compared without case where the file system ignores it.
const CASE_INSENSITIVE: bool = cfg!(any(windows, target_os = "macos"));

impl HookRequest {
    /// This request decided from `session_dir`, the session's working
    /// directory, when its `cwd` is the directory the tool runs in and differs
    /// from it: a shell command runs after a `cd` to that directory, and every
    /// relative path of the action is taken from it. Unchanged when `cwd` is
    /// unset or already `session_dir`.
    #[must_use]
    pub fn from_session_dir(mut self, session_dir: &str) -> Self {
        let tool_dir = match self.cwd.as_deref() {
            Some(dir) if !dir.is_empty() && !same_dir(dir, session_dir) => dir.to_owned(),
            _ => return self,
        };
        self.action = self.action.map(|action| runs_in(action, &tool_dir));
        self.cwd = Some(session_dir.to_owned());
        self
    }

    /// Whether the action holds a search over every directory of the host's
    /// workspace, which the payload does not name: the guard then reads the
    /// directories the host's settings add ([`crate::HostSpec::workspace_dirs`]).
    #[must_use]
    pub fn searches_workspace(&self) -> bool {
        self.action.as_ref().is_some_and(workspace_wide)
    }

    /// This request with each search over the host's workspace reading
    /// `extra`, the directories the host's settings add to the working
    /// directory (relative ones taken from it), instead of needing review for
    /// what the payload does not name. With none, the search reads the working
    /// directory only, as it does on a host without such a setting.
    #[must_use]
    pub fn with_workspace_dirs(mut self, extra: &[String]) -> Self {
        let cwd = self.cwd.clone();
        let extra: Vec<String> = extra
            .iter()
            .filter(|dir| !dir.is_empty())
            .map(|dir| match &cwd {
                Some(cwd) if is_relative(dir) => crate::below(cwd, dir),
                _ => dir.clone(),
            })
            .collect();
        self.action = self.action.map(|action| in_workspace(action, &extra));
        self
    }
}

fn workspace_wide(action: &Action) -> bool {
    match action {
        Action::Unchecked { action, reason } => {
            reason == EVERY_WORKSPACE_DIRECTORY || workspace_wide(action)
        }
        _ => false,
    }
}

/// `action` with each workspace-wide search's mark replaced by reads of `extra`.
fn in_workspace(action: Action, extra: &[String]) -> Action {
    match action {
        Action::Unchecked { action, reason } if reason == EVERY_WORKSPACE_DIRECTORY => {
            let mut paths = match *action {
                Action::FsRead { path } => vec![path],
                Action::ReadFiles { paths } => paths,
                // Workspace searches read files only; anything else keeps its mark.
                other => return Action::unchecked(other, reason),
            };
            for dir in extra {
                if !paths.contains(dir) {
                    paths.push(dir.clone());
                }
            }
            match paths.len() {
                1 => Action::FsRead {
                    path: paths.remove(0),
                },
                _ => Action::ReadFiles { paths },
            }
        }
        Action::Unchecked { action, reason } => {
            Action::unchecked(in_workspace(*action, extra), reason)
        }
        other => other,
    }
}

/// `action` as it runs in `dir`: a shell command after a `cd` there, quoted
/// whole, and each relative path taken from it. A foreign shell's command, an
/// MCP tool's paths (which its server resolves) and URLs stay as they are.
fn runs_in(action: Action, dir: &str) -> Action {
    let join = |path: String| {
        if is_relative(&path) {
            crate::below(dir, &path)
        } else {
            path
        }
    };
    let all = |paths: Vec<String>| paths.into_iter().map(join).collect();
    match action {
        Action::Shell { command } => Action::Shell {
            command: in_dir(dir, &command),
        },
        Action::FsRead { path } => Action::FsRead { path: join(path) },
        Action::FsWrite { path } => Action::FsWrite { path: join(path) },
        Action::ReadFiles { paths } => Action::ReadFiles { paths: all(paths) },
        Action::Patch { writes } => Action::Patch {
            writes: all(writes),
        },
        Action::UnknownTool {
            host,
            tool,
            reads,
            writes,
            hosts,
            commands,
        } => Action::UnknownTool {
            host,
            tool,
            reads: all(reads),
            writes: all(writes),
            hosts,
            commands: commands.iter().map(|c| in_dir(dir, c)).collect(),
        },
        Action::Unchecked { action, reason } => Action::unchecked(runs_in(*action, dir), reason),
        other => other,
    }
}

/// `command` after a `cd` to `dir`, quoted whole: the classifier then resolves
/// its relative paths there, as the shell does.
fn in_dir(dir: &str, command: &str) -> String {
    format!("cd '{}' && {command}", dir.replace('\'', r"'\''"))
}

/// Whether `path` names its place only from a working directory: not absolute
/// (`/`, `\`, `C:`) and not in the home directory (`~`).
pub(crate) fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !(drive || path.starts_with(['/', '\\', '~']))
}

/// `path` in slash form, without a trailing separator, folded where case does
/// not count.
fn folded(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let trimmed = match slashed.trim_end_matches('/') {
        "" => "/",
        rest => rest,
    };
    if CASE_INSENSITIVE {
        trimmed.to_lowercase()
    } else {
        trimmed.to_owned()
    }
}

fn same_dir(a: &str, b: &str) -> bool {
    folded(a) == folded(b)
}

/// Whether the directory `path` is `root` or below it, compared as written: a
/// path with a `..` segment is never taken to be inside, since where it lands
/// depends on the links it walks through.
pub(crate) fn is_inside(path: &str, root: &str) -> bool {
    let (path, root) = (folded(path), folded(root));
    if path.split('/').any(|segment| segment == "..") {
        return false;
    }
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('/') || root.ends_with('/'))
}

#[cfg(test)]
mod tests;
