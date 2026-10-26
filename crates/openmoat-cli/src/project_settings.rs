//! Agent settings a repository carries: Claude Code's `.claude/settings.json`
//! (shared with the project) and `.claude/settings.local.json` (the person's
//! own), GitHub Copilot CLI's `.github/copilot/settings*.json` and the hook
//! files in its `.github/hooks`, Gemini CLI's `.gemini/settings.json`, pi's
//! `.pi/settings.json` and `.pi/extensions`, and OpenCode's `opencode.json`,
//! `.opencode/opencode.json` and `.opencode/plugins`, as each host's spec names them
//! (`HostSpec::project_settings`); and what the person's own settings file of
//! each of those hosts sets that turns OpenMoat's hook off ([`switched_off`]).
//!
//! OpenMoat pins only the user settings file, which holds its hooks. Claude
//! Code merges the project and local files over it, and a key set there wins:
//! `"disableAllHooks": true` in a project file turns OpenMoat's hooks off with
//! every other hook, and a project's own `hooks`, `env` or command helpers run
//! programs or redirect the agent. Repository content is the attacker's
//! (`docs/THREAT_MODEL.md` §2), so a `ConfigChange` that would load such a file
//! mid-session is blocked, and `moat doctor` and `moat status` warn about one
//! Claude Code loaded at start.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{Host, ProjectSettingsSpec, SettingsFile, SettingsReader};
use serde_json::{Map, Value};

use crate::home::Home;
use crate::install::HostConfig;

/// The rule a blocked project settings change and its audit row carry.
pub const RULE: &str = "project-settings";

/// A settings file larger than this is refused unread rather than parsed.
const MAX_BYTES: u64 = 1024 * 1024;

/// What a Claude Code settings file sets that could switch OpenMoat off, run
/// a program or redirect the agent (`openmoat-hosts`, `host/claude_code`):
/// `ConfigChange` is Claude Code's hook, also sent by the Continue CLI.
#[must_use]
pub fn findings(root: &Map<String, Value>) -> Vec<String> {
    openmoat_hosts::claude_code_settings_findings(root)
}

/// How to read one settings file of a host: its reader, the directory its
/// relative entries resolve from, and OpenMoat's hook file, which an entry
/// may name to turn it off (pi).
#[derive(Debug, Clone, Copy)]
pub struct Reading<'a> {
    pub reader: &'static dyn SettingsReader,
    pub base: &'a Path,
    pub hook_file: &'a Path,
}

impl Reading<'_> {
    /// `root` as the file the host's reader is handed.
    fn file<'r>(
        &'r self,
        root: &'r Map<String, Value>,
        home: Option<&'r Path>,
    ) -> SettingsFile<'r> {
        SettingsFile::new(root, self.base, self.hook_file, home)
    }

    /// What a project's file `root` sets that [`findings`] names, in this format.
    fn findings(&self, root: &Map<String, Value>) -> Vec<String> {
        let home = crate::home::user_home().ok();
        self.reader.findings(&self.file(root, home.as_deref()))
    }

    /// What the person's own file `root` sets that turns OpenMoat's hook off.
    fn switched_off(&self, root: &Map<String, Value>) -> Vec<String> {
        let home = crate::home::user_home().ok();
        self.reader.switched_off(&self.file(root, home.as_deref()))
    }
}

/// What `host`'s own settings file in its configuration directory
/// ([`ProjectSettingsSpec::user_file`]) sets that turns OpenMoat's hook off,
/// or why it could not be read; `None` when it is absent or turns nothing off.
/// The host reads it at every start, so a hook that is installed and pinned
/// may still never run.
#[must_use]
pub fn switched_off(host: Host, config_dir: &Path, hook_file: &Path) -> Option<String> {
    let spec = host.spec().project_settings.as_ref()?;
    let path = config_dir.join(spec.user_file);
    let reading = Reading {
        reader: spec.reader,
        base: config_dir,
        hook_file,
    };
    let found = match read_bytes(&path) {
        Ok(None) => return None,
        Ok(Some(bytes)) => match parse(&path, &bytes, spec.reader.reads_comments()) {
            Ok(root) => reading.switched_off(&root),
            Err(e) => vec![format!("cannot be checked: {e:#}")],
        },
        Err(e) => vec![format!("cannot be checked: {e:#}")],
    };
    (!found.is_empty()).then(|| format!("{}: {}", path.display(), found.join("; ")))
}

/// The bytes of `path`, or `None` when there is no such file (a deleted file
/// loads nothing); an error for anything else that cannot be read and for a
/// file larger than [`MAX_BYTES`].
fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("{} is larger than {MAX_BYTES} bytes", path.display());
    }
    Ok(Some(bytes))
}

/// The settings object `bytes` (read from `path`) hold; an error for text that
/// is not one JSON object. With `comments`, the host reads its files as JSON
/// with comments and trailing commas (OpenCode), read here as JSON5.
fn parse(path: &Path, bytes: &[u8], comments: bool) -> Result<Map<String, Value>> {
    if comments {
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("{} is not UTF-8", path.display()))?;
        let parsed = crate::install::openclaw::parse(text)
            .with_context(|| format!("{} is not valid JSON with comments", path.display()))?;
        return match parsed.value {
            Value::Object(root) => Ok(root),
            _ => bail!("{} is not a JSON object", path.display()),
        };
    }
    if path.extension().is_some_and(|e| e == "toml") {
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("{} is not UTF-8", path.display()))?;
        let doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("{} is not valid TOML", path.display()))?;
        return match crate::mcp::servers::toml_to_json(doc.as_item()) {
            Value::Object(root) => Ok(root),
            _ => bail!("{} is not a TOML table", path.display()),
        };
    }
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(root)) => Ok(root),
        Ok(_) => bail!("{} is not a JSON object", path.display()),
        Err(e) => Err(e).with_context(|| format!("{} is not valid JSON", path.display())),
    }
}

/// What the bytes of one Claude Code file set that [`findings`] names, or why
/// they could not be read; `None` when the file is absent or sets nothing risky.
fn judge(path: &Path, bytes: Option<&[u8]>) -> Option<String> {
    judge_with(path, bytes, false, findings)
}

/// [`judge`] with `found` naming what is risky, in JSON with comments when
/// `comments` ([`parse`]).
fn judge_with(
    path: &Path,
    bytes: Option<&[u8]>,
    comments: bool,
    found: impl Fn(&Map<String, Value>) -> Vec<String>,
) -> Option<String> {
    match bytes.map(|bytes| parse(path, bytes, comments)) {
        None => None,
        Some(Ok(root)) => {
            let found = found(&root);
            (!found.is_empty()).then(|| found.join("; "))
        }
        Some(Err(e)) => Some(format!("cannot be checked: {e:#}")),
    }
}

/// What reading one Claude Code file found: the risky keys it sets, or why it
/// could not be read. `None` when the file is absent or sets nothing risky.
#[cfg(test)]
fn check(path: &Path) -> Option<String> {
    check_as(path, false, findings)
}

/// What reading one file found, `found` naming what is risky in its format
/// (JSON with comments when `comments`): what it sets, or why it could not be
/// read; `None` when the file is absent or sets nothing risky.
fn check_as(
    path: &Path,
    comments: bool,
    found: impl Fn(&Map<String, Value>) -> Vec<String>,
) -> Option<String> {
    match read_bytes(path) {
        Ok(bytes) => judge_with(path, bytes.as_deref(), comments, found),
        Err(e) => Some(format!("cannot be checked: {e:#}")),
    }
}

/// What reading one Claude Code file found, for a decision: a file that passes is read once more just before
/// the decision, and one whose bytes changed in between (or that appeared or
/// went) is reported, since what the host loads may not be what was checked.
#[must_use]
pub fn check_unchanged(path: &Path) -> Option<String> {
    check_between(path, || {})
}

/// [`check_unchanged`] with `between` run after the first read.
fn check_between(path: &Path, between: impl FnOnce()) -> Option<String> {
    let first = match read_bytes(path) {
        Ok(bytes) => bytes,
        Err(e) => return Some(format!("cannot be checked: {e:#}")),
    };
    if let Some(found) = judge(path, first.as_deref()) {
        return Some(found);
    }
    between();
    match read_bytes(path) {
        Ok(second) if second == first => None,
        Ok(_) => Some("changed while OpenMoat was checking it".to_owned()),
        Err(e) => Some(format!("cannot be checked: {e:#}")),
    }
}

/// The project settings files a host may load for a session in `cwd`: those
/// of `cwd` and of its project root (`project.rs`) in the directory `spec`
/// names, named `name` (one of [`ProjectSettingsSpec::files`]), existing or
/// not. A directory that cannot be a project root (the home directory, which
/// holds the user settings, or an ancestor of it) has none.
#[must_use]
pub fn candidates(
    cwd: &Path,
    user_home: &Path,
    spec: &ProjectSettingsSpec,
    name: &str,
) -> Vec<PathBuf> {
    project_dirs(cwd, user_home)
        .into_iter()
        .map(|dir| dir.join(spec.dir).join(name))
        .collect()
}

/// `cwd` and its project root, each only when it can be a project root.
fn project_dirs(cwd: &Path, user_home: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = vec![cwd.to_path_buf()];
    if let Some(root) = crate::project::root_of(cwd, user_home)
        && !dirs.contains(&root)
    {
        dirs.push(root);
    }
    dirs.retain(|dir| crate::project::trusted(dir, user_home));
    dirs
}

/// Every file in `dir` with one of `extensions`, and every directory in it
/// holding an `index` file with one (pi loads `index.ts` of a directory),
/// sorted; none when `dir` cannot be read.
fn hook_files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let known = |path: &Path| {
        path.extension()
            .is_some_and(|e| extensions.iter().any(|x| e == *x))
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| {
            (known(path) && path.is_file())
                || (path.is_dir()
                    && extensions
                        .iter()
                        .any(|x| path.join(format!("index.{x}")).is_file()))
        })
        .collect();
    files.sort();
    files
}

/// One warning per project settings file `host`'s spec names for `cwd` that
/// sets something [`findings`] names or cannot be read, and one per hook file
/// in its project hook directory, for `moat doctor` and `moat status`. The
/// host loads these when a session starts, where no `ConfigChange` fires, so
/// OpenMoat can only point at them. `hook_file` is OpenMoat's own, which a
/// pi project entry may name to turn it off.
#[must_use]
pub fn warnings(cwd: &Path, user_home: &Path, host: Host, hook_file: &Path) -> Vec<String> {
    let Some(spec) = host.spec().project_settings.as_ref() else {
        return Vec::new();
    };
    let row = |path: &Path, found: &str| {
        format!(
            "{}: {found}. A {} session started here loads it; review the file \
             and remove what you did not add",
            path.display(),
            host.display_name()
        )
    };
    let mut rows: Vec<String> = Vec::new();
    for name in spec.files() {
        for path in candidates(cwd, user_home, spec, name) {
            let base = path.parent().unwrap_or(&path).to_path_buf();
            let reading = Reading {
                reader: spec.reader,
                base: &base,
                hook_file,
            };
            if let Some(found) = check_as(&path, spec.reader.reads_comments(), |root| {
                reading.findings(root)
            }) {
                rows.push(row(&path, &found));
            }
        }
    }
    if let Some(dir) = &spec.hook_dir {
        let what = spec.reader.hook_dir_effect();
        for path in project_dirs(cwd, user_home).into_iter().flat_map(|root| {
            dir.paths()
                .flat_map(move |path| hook_files(&root.join(path), dir.extensions))
        }) {
            rows.push(row(&path, what));
        }
    }
    rows
}

/// One [`warnings`] line and the host whose project settings it is about.
pub struct Warning {
    pub host: Host,
    pub text: String,
}

/// [`warnings`] for the current directory, for every host with project
/// settings in its spec, for `moat doctor` and `moat status`; empty when the
/// directory or the home directory cannot be found.
#[must_use]
pub fn warnings_here(home: &Home) -> Vec<Warning> {
    let (Ok(cwd), Ok(user_home)) = (std::env::current_dir(), crate::home::user_home()) else {
        return Vec::new();
    };
    Host::ALL
        .into_iter()
        .filter_map(|host| Some((host, HostConfig::for_host(home, host).ok()?)))
        .flat_map(|(host, config)| {
            warnings(&cwd, &user_home, host, &config.settings_path)
                .into_iter()
                .map(move |text| Warning { host, text })
        })
        .collect()
}

#[cfg(test)]
mod tests;
