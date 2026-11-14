//! OpenMoat's hook in the place an administrator's hooks live
//! (`HostSpec::hook_off`'s `Managed::Written`, ADR-098): a file a project's
//! settings cannot turn off, written by `openmoat init --managed`, reported by
//! `openmoat doctor`, removed by `openmoat uninstall`.
//!
//! The file holds what `openmoat init` writes into the person's own hook
//! file, started from an empty one: the host reads both in the same format.
//! A system directory needs root, and OpenMoat never escalates: where it
//! cannot write the file itself, or the host loads it only when root owns it,
//! it keeps the file under its state directory and prints the command that
//! installs it. An administrator's own file is never edited.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{Host, Managed, ManagedHooks, Platform, SystemFile};
use serde_json::Value;

use crate::home::Home;
use crate::install::HostConfig;

mod command;
// Who may read a file written in place: every account the host runs for.
#[cfg(not(unix))]
mod mode_other;
#[cfg(unix)]
mod mode_unix;
#[cfg(test)]
mod tests;

#[cfg(not(unix))]
use mode_other as mode;
#[cfg(unix)]
use mode_unix as mode;

pub use command::install_command;

/// Debug builds read the system directories under this directory instead,
/// so end-to-end tests never touch the real ones. Release builds do not
/// contain the check.
#[cfg(debug_assertions)]
const TEST_ROOT: &str = "MOAT_TEST_SYSTEM_ROOT";

/// `host`'s managed hook facts, when OpenMoat writes them.
#[must_use]
pub fn hooks_of(host: Host) -> Option<&'static ManagedHooks> {
    match &host.spec().hook_off.managed {
        Managed::Written(hooks) => Some(hooks),
        Managed::Manual { .. } | Managed::None { .. } => None,
    }
}

/// The path a system file is read at on this machine.
#[must_use]
pub fn system_path(file: &SystemFile) -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os(TEST_ROOT).filter(|v| !v.is_empty()) {
        let rel = file
            .path
            .split_once(":/")
            .map_or(file.path, |(_, rest)| rest);
        return PathBuf::from(root).join(rel.trim_start_matches('/'));
    }
    PathBuf::from(file.path)
}

/// The first of `files` this platform reads, where it is read.
fn on_this_platform(files: &[SystemFile], platform: Platform) -> Option<PathBuf> {
    files
        .iter()
        .find(|file| file.platforms.contains(&platform))
        .map(system_path)
}

/// Where `hooks`' file is on this machine; `None` on a platform the host
/// reads none on.
#[must_use]
pub fn target(hooks: &ManagedHooks) -> Option<PathBuf> {
    on_this_platform(hooks.files, crate::os_version::platform())
}

/// A source of `hooks` that, present, makes the host skip the file.
#[must_use]
pub fn shadow(hooks: &ManagedHooks) -> Option<PathBuf> {
    let platform = crate::os_version::platform();
    hooks
        .shadowed_by
        .iter()
        .filter(|file| file.platforms.contains(&platform))
        .map(system_path)
        .find(|path| path.exists())
}

/// Where `init --managed` keeps a file it could not put in place itself.
fn staged_path(home: &Home, host: Host) -> PathBuf {
    home.root()
        .join("managed")
        .join(format!("{}.json", host.id()))
}

/// The document the managed file holds for `config`'s hook running `binary`.
fn content(config: &HostConfig, binary: &Path) -> Result<String> {
    match config.render(binary, "")? {
        Some(text) => Ok(text),
        None => bail!("no hook document for {}", config.host.display_name()),
    }
}

/// The bytes at `path`; `None` when there is no file. An error for any other
/// failure to read, a file that cannot be read included.
fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether `bytes` hold OpenMoat's hook entries for `config` and nothing
/// else (a `version` aside): what the file holds once they are removed is
/// empty. Text that is not JSON is not OpenMoat's.
fn only_ours(config: &HostConfig, bytes: &[u8]) -> bool {
    let Ok(mut root) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    config.remove(&mut root) && empty(&root)
}

/// A value that holds no entry: `null`, an empty list, an object of such
/// values, or a top-level `version` number.
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().all(empty),
        Value::Object(map) => map
            .iter()
            .all(|(key, v)| (key == "version" && v.is_number()) || empty(v)),
        _ => false,
    }
}

/// The managed file's state for `config`'s hook running `binary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The host reads no such file on this platform.
    NoPlace,
    /// It holds what `init --managed` writes.
    Current(PathBuf),
    /// There is none.
    Missing(PathBuf),
    /// It holds an older OpenMoat hook.
    Outdated(PathBuf),
    /// It holds an administrator's own hooks, which OpenMoat never edits.
    Theirs(PathBuf),
    /// It cannot be read: root may read it alone.
    Unreadable(PathBuf, String),
}

/// [`State`] of `host`'s managed file.
pub fn state(hooks: &ManagedHooks, config: &HostConfig, binary: &Path) -> Result<State> {
    let Some(path) = target(hooks) else {
        return Ok(State::NoPlace);
    };
    let want = content(config, binary)?;
    Ok(match read(&path) {
        Ok(None) => State::Missing(path),
        Ok(Some(bytes)) if bytes == want.as_bytes() => State::Current(path),
        Ok(Some(bytes)) if only_ours(config, &bytes) => State::Outdated(path),
        Ok(Some(_)) => State::Theirs(path),
        Err(e) => State::Unreadable(path, e.to_string()),
    })
}

/// What `init --managed` did for one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// The file already held OpenMoat's hook.
    Unchanged(PathBuf),
    /// It was written (or would be, in a dry run).
    Written(PathBuf),
    /// It is kept at `staged` until a person runs `command`.
    Staged {
        target: PathBuf,
        staged: PathBuf,
        command: String,
    },
    /// It was left alone, for the reason given.
    Skipped(String),
}

/// Put `config`'s hook running `binary` in `host`'s managed file, or keep it
/// under the state directory with the command that installs it.
pub fn install(home: &Home, config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Done> {
    let host = config.host;
    let Some(hooks) = hooks_of(host) else {
        return Ok(Done::Skipped(format!(
            "{} has no managed hook file OpenMoat writes",
            host.display_name()
        )));
    };
    let target = match state(hooks, config, binary)? {
        State::NoPlace => {
            return Ok(Done::Skipped(format!(
                "{} reads no managed hook file on this platform",
                host.display_name()
            )));
        }
        State::Current(path) => return Ok(Done::Unchanged(path)),
        State::Theirs(path) => {
            return Ok(Done::Skipped(format!(
                "{} holds an administrator's own hooks, which OpenMoat does not edit; add \
                 OpenMoat's entries from {} to it",
                path.display(),
                config.settings_path.display()
            )));
        }
        // A file OpenMoat cannot read may be an administrator's: never a
        // place to write, whatever its shape (ADR-098).
        State::Unreadable(path, why) => {
            return Ok(Done::Skipped(format!(
                "{} cannot be read ({why}), so OpenMoat cannot tell whose it is and leaves it \
                 alone; an administrator can add OpenMoat's entries from {} to it",
                path.display(),
                config.settings_path.display()
            )));
        }
        State::Missing(path) | State::Outdated(path) => path,
    };
    if dry_run {
        return Ok(Done::Written(target));
    }
    let text = content(config, binary)?;
    if !hooks.root_owned && mode::write_readable(&target, text.as_bytes()).is_ok() {
        return Ok(Done::Written(target));
    }
    let staged = staged_path(home, host);
    crate::home::write_private(&staged, text.as_bytes())
        .with_context(|| format!("keeping {}", staged.display()))?;
    let digest = crate::integrity::sha256_hex(text.as_bytes());
    let command = install_command(&staged, &digest, &target, crate::os_version::platform());
    Ok(Done::Staged {
        target,
        staged,
        command,
    })
}

/// What `openmoat uninstall` did with `config`'s managed file: `None` when
/// there is none of OpenMoat's.
pub fn uninstall(home: &Home, config: &HostConfig) -> Option<String> {
    let host = config.host;
    let hooks = hooks_of(host)?;
    let staged = staged_path(home, host);
    // Kept only until a person installs it.
    let _ = fs::remove_file(&staged);
    let target = target(hooks)?;
    let bytes = read(&target).ok()??;
    // A drop-in's name is OpenMoat's and a whole file is written only while
    // it holds OpenMoat's hook alone; either way, what an administrator added
    // since stays.
    if !only_ours(config, &bytes) {
        return Some(format!(
            "{} holds more than OpenMoat's hook and was kept",
            target.display()
        ));
    }
    Some(match fs::remove_file(&target) {
        Ok(()) => format!("{} removed", target.display()),
        Err(_) => format!(
            "{} needs an administrator to remove it, or {} keeps running OpenMoat's hook: {}",
            target.display(),
            host.display_name(),
            command::remove_command(&target, crate::os_version::platform())
        ),
    })
}

/// One row of `openmoat doctor` about a managed hook file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    /// All is as it should be, or an option the person has.
    Note(String),
    /// Something the person should act on.
    Warn(String),
}

/// `openmoat doctor`'s rows for each set-up host whose managed hook file
/// OpenMoat writes.
pub fn doctor_rows(home: &Home, binary: &Path) -> Vec<Row> {
    crate::mcp::set_up_hosts(home, binary)
        .into_iter()
        .filter_map(|host| {
            let hooks = hooks_of(host)?;
            let config = HostConfig::for_host(home, host).ok()?;
            let state = state(hooks, &config, binary).ok()?;
            row(home, host, hooks, &state)
        })
        .collect()
}

/// The doctor row for `host` in `state`.
fn row(home: &Home, host: Host, hooks: &ManagedHooks, state: &State) -> Option<Row> {
    let name = format!("{:<16} managed hook", host.display_name());
    let holds = if hooks.outlasts_project {
        "a project's settings cannot turn it off"
    } else {
        "it outranks the person's own hooks"
    };
    let staged = staged_path(home, host);
    Some(match state {
        State::NoPlace => return None,
        State::Current(path) => match shadow(hooks) {
            Some(shadow) => Row::Warn(format!(
                "{name} {} holds OpenMoat's hook, but {} is present and {} applies that source \
                 instead of the file",
                path.display(),
                shadow.display(),
                host.display_name()
            )),
            None if hooks.unseen_shadows.is_empty() => {
                Row::Note(format!("{name} {}: {holds}", path.display()))
            }
            None => Row::Note(format!(
                "{name} {}: {holds}, unless {} supply a policy, which {} applies instead",
                path.display(),
                hooks.unseen_shadows,
                host.display_name()
            )),
        },
        State::Missing(path) | State::Outdated(path) if staged.exists() => {
            let digest = fs::read(&staged)
                .map(|bytes| crate::integrity::sha256_hex(&bytes))
                .unwrap_or_default();
            Row::Warn(format!(
                "{name} {} is not in place yet; run: {}",
                path.display(),
                install_command(&staged, &digest, path, crate::os_version::platform())
            ))
        }
        State::Missing(path) => Row::Note(format!(
            "{name} `openmoat init --managed` writes OpenMoat's hook to {}, where {holds}",
            path.display()
        )),
        State::Outdated(path) => Row::Warn(format!(
            "{name} {} holds an older OpenMoat hook; run `openmoat init --managed`",
            path.display()
        )),
        State::Theirs(path) => Row::Note(format!(
            "{name} {} holds an administrator's own hooks; OpenMoat's are not among them",
            path.display()
        )),
        State::Unreadable(path, why) => {
            Row::Note(format!("{name} {} cannot be read ({why})", path.display()))
        }
    })
}

/// Whether `host`'s managed file holds OpenMoat's current hook and no source
/// the host applies instead is present, and the host's documentation says a
/// project's settings cannot turn it off: then a project file that turns the
/// person's own hook off leaves OpenMoat's running (`openmoat run`'s
/// pre-flight).
pub fn outlasts_project(config: &HostConfig, binary: &Path) -> bool {
    hooks_of(config.host).is_some_and(|hooks| {
        hooks.outlasts_project
            && shadow(hooks).is_none()
            && matches!(state(hooks, config, binary), Ok(State::Current(_)))
    })
}
