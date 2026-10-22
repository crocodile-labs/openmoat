//! Host hook installation.

mod binary;
mod claude_version;
mod dirs;
mod hook_file;
pub mod location;
pub mod openclaw;
pub mod pi;
pub mod self_paths;
pub mod trust_note;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{Host, InstallSpec, Locate, Located};

pub use binary::{alias_of, hook_binary, other_name, stale_hint};
pub use dirs::Recorded;
pub use hook_file::{HookState, Outcome, read_or_empty};
pub use openmoat_hosts::{GUARD_BUDGET_S, HookFormat, HookSpec};

use crate::home::{Home, user_home};

/// Suffix of the copy of a host file taken before OpenMoat's hook edit changes it.
pub const HOOK_BACKUP: &str = "moat-backup";
/// Suffix of the copy taken before OpenMoat's sandbox edit changes it.
pub const SANDBOX_BACKUP: &str = "moat-sandbox-backup";

/// The copy of `path` named `<path>.<suffix>`.
pub fn backup_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Copy `path` to its `suffix` backup before OpenMoat edits it, unless
/// something is at the backup's name, and record the copy in `hosts.json`.
/// The first one holds the file as it was before OpenMoat touched it; a later
/// copy would replace it with an already edited file. A file of the user's at
/// that name is left alone, and a link there is never followed.
pub fn back_up(home: &Home, path: &Path, suffix: &str) -> Result<()> {
    let backup = backup_path(path, suffix);
    if !path.exists() || fs::symlink_metadata(&backup).is_ok() {
        return Ok(());
    }
    fs::copy(path, &backup).with_context(|| format!("backing up {}", path.display()))?;
    let mut recorded = Recorded::load(home)?;
    recorded.backups.push(backup);
    recorded.save(home)
}

/// The files at `path`'s backup names, hook backup first. OpenMoat created
/// only those [`Recorded::owns`]; any of them may still hold the original.
pub fn backups(path: &Path) -> Vec<PathBuf> {
    [HOOK_BACKUP, SANDBOX_BACKUP]
        .into_iter()
        .map(|suffix| backup_path(path, suffix))
        .filter(|p| p.is_file())
        .collect()
}

/// Where a host keeps its hook configuration and which events we subscribe to.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub host: Host,
    pub settings_path: PathBuf,
    /// The configuration directory `hosts.json` records: the hook file's, or
    /// OpenClaw's state directory, which holds OpenMoat's plugin and holds
    /// `openclaw.json` unless `OPENCLAW_CONFIG_PATH` puts it elsewhere.
    pub dir: PathBuf,
    pub hooks: &'static [HookSpec],
    pub format: HookFormat,
    /// Whether the host's version knows `onFailure`; asked only when an
    /// entry with [`HookSpec::block_on_failure`] lacks the key, so commands
    /// that never compare entries (`uninstall`) never ask.
    pub blocks_on_failure: fn() -> bool,
}

/// The environment variable that moves `host`'s configuration directory, and
/// the directory's name under the home directory otherwise.
pub fn dir_variable(host: Host) -> Result<(&'static str, &'static str)> {
    let install = install_spec(host)?;
    Ok((install.dir_variable, install.dir_name))
}

/// Where `host` keeps the configuration its hook goes into.
fn install_spec(host: Host) -> Result<&'static InstallSpec> {
    match &host.spec().install {
        Some(install) => Ok(install),
        None => bail!(
            "{} runs another agent's hook; it has none of its own",
            host.display_name()
        ),
    }
}

/// `host`'s configuration directory as named by this shell's environment,
/// when its variable is set (for a host with its own location rules, any of
/// their variables; for a variable that names a home, the directory's name
/// inside it).
pub fn env_config_dir(host: Host) -> Result<Option<PathBuf>> {
    if let Some(locate) = location::custom(host) {
        return Ok(location::from_env(locate)?.map(|l| l.dir));
    }
    let install = install_spec(host)?;
    let dir = env_dir(install.dir_variable);
    Ok(if install.variable_names_home() {
        dir.map(|home| home.join(install.dir_name))
    } else {
        dir
    })
}

impl HostConfig {
    /// `host`'s configuration where `moat init` recorded it (`hosts.json`), else
    /// where this shell's environment or the default puts it.
    pub fn for_host(home: &Home, host: Host) -> Result<Self> {
        let recorded = Recorded::load(home)?;
        if let Some(locate) = location::custom(host) {
            let located = match recorded.dir(host) {
                Some(dir) => locate.at(dir, recorded.file(host)),
                None => match location::from_env(locate)? {
                    Some(located) => located,
                    None => locate.default_for(&user_home()?),
                },
            };
            return Self::with_spec(host, located.config, located.dir);
        }
        Self::at(host, recorded.dir(host).or(env_config_dir(host)?))
    }

    /// For `moat init`: this shell's environment wins over the record, so a
    /// person moves an agent by running `init` with its variable set.
    pub fn for_init(home: &Home, host: Host) -> Result<Self> {
        if let Some(locate) = location::custom(host)
            && let Some(located) = location::from_env(locate)?
        {
            return Self::with_spec(host, located.config, located.dir);
        }
        match env_config_dir(host)? {
            Some(dir) => Self::at(host, Some(dir)),
            None => Self::for_host(home, host),
        }
    }

    /// The configuration directory and hook file of a host with its own
    /// location rules (OpenClaw's state directory and `openclaw.json`), with
    /// those rules; `None` for any other host.
    pub fn custom_location(&self) -> Option<(&'static dyn Locate, Located)> {
        let locate = location::custom(self.host)?;
        Some((
            locate,
            locate.at(self.dir.clone(), Some(self.settings_path.clone())),
        ))
    }

    /// `host` with its hook file in `dir`, or in its default directory.
    fn at(host: Host, dir: Option<PathBuf>) -> Result<Self> {
        let install = install_spec(host)?;
        let dir = match dir {
            Some(dir) => dir,
            None => user_home()?.join(install.dir_name),
        };
        Self::with_spec(host, dir.join(install.config_file), dir)
    }

    /// `host` with its hook file at `settings_path` and `dir` as [`Self::dir`]
    /// (for OpenClaw, `openclaw.json` wherever it is and the state directory),
    /// writing the entries and layout its spec names.
    fn with_spec(host: Host, settings_path: PathBuf, dir: PathBuf) -> Result<Self> {
        let install = install_spec(host)?;
        // Only Claude Code's entries ask for `onFailure`, and whether its
        // version knows the key is asked of the `claude` on `PATH`.
        let blocks_on_failure: fn() -> bool =
            if install.hooks.iter().any(|spec| spec.block_on_failure) {
                claude_version::blocks_on_failure
            } else {
                || false
            };
        Ok(Self {
            host,
            settings_path,
            dir,
            hooks: install.hooks,
            format: install.hook_format,
            blocks_on_failure,
        })
    }

    /// The configuration directory, the one `hosts.json` records.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The host is considered present when its configuration directory exists.
    pub fn host_present(&self) -> bool {
        self.dir.is_dir()
    }

    /// Install the hook, recording any backup in `home`'s `hosts.json`.
    pub fn install(&self, home: &Home, binary: &Path, dry_run: bool) -> Result<Outcome> {
        hook_file::install(home, self, binary, dry_run)
    }

    /// The hook file's text `current` as [`Self::install`] would write it;
    /// `None` when it would not change.
    pub fn render(&self, binary: &Path, current: &str) -> Result<Option<String>> {
        hook_file::render(self, binary, current)
    }

    pub fn state(&self, binary: &std::path::Path) -> HookState {
        hook_file::state(self, binary)
    }

    /// Whether the host is set up: OpenMoat's hook for `binary` is installed
    /// there. Only then do `moat sandbox sync`, `status` and `doctor` deal with
    /// its sandbox settings; the files of any other host are never touched.
    pub fn set_up(&self, binary: &std::path::Path) -> bool {
        self.state(binary) == HookState::Installed
    }

    /// Whether the installed hook runs the `moat` alias of `binary` rather
    /// than `binary` itself: written before the rename, it still works, and
    /// `openmoat init` rewrites it.
    pub fn runs_alias(&self, binary: &Path) -> bool {
        hook_file::runs_alias(self, binary)
    }

    /// Remove OpenMoat's hook entries from the parsed hook file `root`.
    pub fn remove(&self, root: &mut serde_json::Value) -> bool {
        hook_file::remove(root, self)
    }

    /// Whether an installed entry that should block the call when `moat guard`
    /// fails lacks `onFailure`, because this host's version does not know it
    /// or no `claude` is on `PATH`: the host then runs a call whose hook failed.
    pub fn runs_calls_when_hook_fails(&self) -> bool {
        hook_file::lacks_on_failure(self)
    }
}

/// What `moat doctor` and `moat status` say when the Continue CLI is present.
pub fn continue_cli_warning() -> &'static str {
    Host::Continue.spec().gaps
}

/// Where the Continue CLI (`cn`) shows itself: its global directory
/// (`CONTINUE_GLOBAL_DIR`, else `~/.continue`, as `cn` resolves it), or `cn`
/// on the search path. `cn` loads Claude Code's hooks but fires none of them
/// yet (released 1.5.47), so its tool calls never reach `guard`.
pub fn continue_cli() -> Result<Option<PathBuf>> {
    let dir = match env_dir("CONTINUE_GLOBAL_DIR") {
        Some(dir) => dir,
        None => user_home()?.join(".continue"),
    };
    if dir.is_dir() {
        return Ok(Some(dir));
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    Ok(crate::environment::find_in(&path, &[], "cn"))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
