//! Agent settings a repository carries: Claude Code's `.claude/settings.json`
//! (shared with the project) and `.claude/settings.local.json` (the person's
//! own), GitHub Copilot CLI's `.github/copilot/settings*.json` and the hook
//! files in its `.github/hooks`, as each host's spec names them
//! (`HostSpec::project_settings`).
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
use openmoat_hosts::{Host, ProjectSettingsSpec};
use serde_json::{Map, Value};

/// The rule a blocked project settings change and its audit row carry.
pub const RULE: &str = "project-settings";

/// A settings file larger than this is refused unread rather than parsed.
const MAX_BYTES: u64 = 1024 * 1024;

/// Keys that name a command Claude Code runs, each with what it is for.
const COMMAND_KEYS: [(&str, &str); 7] = [
    ("apiKeyHelper", "the command that makes the API key"),
    (
        "awsAuthRefresh",
        "the command that refreshes AWS credentials",
    ),
    (
        "awsCredentialExport",
        "the command that exports AWS credentials",
    ),
    (
        "otelHeadersHelper",
        "the command that makes telemetry headers",
    ),
    ("statusLine", "a status line command"),
    ("subagentStatusLine", "a subagent status line command"),
    ("fileSuggestion", "a file suggestion command"),
];

/// What a project settings file sets that could switch OpenMoat off, run a
/// program or redirect the agent; empty when it sets none of that.
///
/// Permission lists and modes are left out on purpose: they decide only
/// whether Claude Code asks the person itself about a call the hook left to
/// it, and Claude Code runs the `PreToolUse` hook in every mode, so OpenMoat's
/// deny and ask stand whatever a project allows. MCP servers a project adds
/// are held by their own pins (ADR-026).
#[must_use]
pub fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = Vec::new();
    if root
        .get("disableAllHooks")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        found.push("`disableAllHooks` turns off every hook, OpenMoat's included".to_owned());
    }
    if set(root.get("hooks")) {
        found.push("`hooks` adds hooks that run commands".to_owned());
    }
    if set(root.get("env")) {
        found.push(
            "`env` sets environment variables for the session (an API endpoint, a key, a proxy)"
                .to_owned(),
        );
    }
    for (key, what) in COMMAND_KEYS {
        if set(root.get(key)) {
            found.push(format!("`{key}` sets {what}"));
        }
    }
    if root
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .is_some_and(|plugins| plugins.values().any(|v| v != &Value::Bool(false)))
    {
        found.push("`enabledPlugins` turns on plugins, which can carry hooks".to_owned());
    }
    if root.get("sandbox").is_some_and(|v| !only_enables(v)) {
        found.push("`sandbox` changes Claude Code's sandbox settings".to_owned());
    }
    found
}

/// A value that sets something: not `null`, `false`, `""`, `{}` or `[]`.
fn set(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

/// `{"enabled": true}` (or nothing at all): a project may turn the sandbox on,
/// never widen or turn off what it allows.
fn only_enables(sandbox: &Value) -> bool {
    match sandbox {
        Value::Null => true,
        Value::Object(o) => o
            .iter()
            .all(|(k, v)| k == "enabled" && v == &Value::Bool(true)),
        _ => false,
    }
}

/// The settings object in `path`, or `None` when there is no such file (a
/// deleted file loads nothing). Anything else that cannot be read, a file
/// larger than [`MAX_BYTES`], or text that is not one JSON object is an error.
pub fn read(path: &Path) -> Result<Option<Map<String, Value>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    if text.len() as u64 > MAX_BYTES {
        bail!("{} is larger than {MAX_BYTES} bytes", path.display());
    }
    match serde_json::from_str(&text) {
        Ok(Value::Object(root)) => Ok(Some(root)),
        Ok(_) => bail!("{} is not a JSON object", path.display()),
        Err(e) => Err(e).with_context(|| format!("{} is not valid JSON", path.display())),
    }
}

/// What reading one file found: the risky keys it sets, or why it could not be
/// read. `None` when the file is absent or sets nothing risky.
#[must_use]
pub fn check(path: &Path) -> Option<String> {
    match read(path) {
        Ok(None) => None,
        Ok(Some(root)) => {
            let found = findings(&root);
            (!found.is_empty()).then(|| found.join("; "))
        }
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

/// Every `*.json` file in `dir`, sorted; none when `dir` cannot be read.
fn hook_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "json") && path.is_file())
        .collect();
    files.sort();
    files
}

/// One warning per project settings file `host`'s spec names for `cwd` that
/// sets something [`findings`] names or cannot be read, and one per hook file
/// in its project hook directory, for `moat doctor` and `moat status`. The
/// host loads these when a session starts, where no `ConfigChange` fires, so
/// OpenMoat can only point at them.
#[must_use]
pub fn warnings(cwd: &Path, user_home: &Path, host: Host) -> Vec<String> {
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
    let mut rows: Vec<String> = spec
        .files()
        .iter()
        .flat_map(|name| candidates(cwd, user_home, spec, name))
        .filter_map(|path| check(&path).map(|found| row(&path, &found)))
        .collect();
    if let Some(dir) = spec.hook_dir {
        for path in project_dirs(cwd, user_home)
            .into_iter()
            .flat_map(|root| hook_files(&root.join(dir)))
        {
            rows.push(row(&path, "adds hooks that run commands"));
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
pub fn warnings_here() -> Vec<Warning> {
    let (Ok(cwd), Ok(user_home)) = (std::env::current_dir(), crate::home::user_home()) else {
        return Vec::new();
    };
    Host::ALL
        .into_iter()
        .flat_map(|host| {
            warnings(&cwd, &user_home, host)
                .into_iter()
                .map(move |text| Warning { host, text })
        })
        .collect()
}

#[cfg(test)]
mod tests;
