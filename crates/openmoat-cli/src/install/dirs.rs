//! `hosts.json`: the configuration directory of each agent `moat init` set up.
//!
//! Every later command reads the agent's files there, whatever this shell's
//! agents' directory variables (each spec's `InstallSpec::dir_variable`) say, so nobody has to
//! export them again (#298); `moat doctor` reports a variable that disagrees.
//! The lock pins the file like the policy.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{AlsoDir, Host};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};

const VERSION: u32 = 1;

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recorded {
    pub version: u32,
    /// Host id → configuration directory.
    pub dirs: BTreeMap<String, PathBuf>,
    /// Host id → configuration file, for one that is not the default file in
    /// its directory (OpenClaw's `OPENCLAW_CONFIG_PATH`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, PathBuf>,
    /// The `permissions.deny` rules OpenMoat added to Claude Code's settings,
    /// so `moat uninstall` removes those and never a rule of the user's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claude_rules: Vec<String>,
    /// The backups OpenMoat created, so `moat uninstall` deletes those and never
    /// a file of the user's that has a backup's name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<PathBuf>,
    /// The MCP server definitions `moat mcp wrap` pointed at `moat mcp proxy`, so
    /// `moat uninstall` restores those and no other.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_wrapped: Vec<crate::mcp::wrap::Wrapped>,
    /// Host id → the further directories `moat init` found that the host
    /// reads laid out like its configuration directory (OpenCode's
    /// `OPENCODE_CONFIG_DIR`, Hermes Agent's profiles: `InstallSpec::also_dirs`),
    /// which the rules naming that directory cover too.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub also: BTreeMap<String, Vec<PathBuf>>,
}

impl Recorded {
    /// The record in `home`; empty when `init` has not written one. From the
    /// bytes the lock check kept when it kept them ([`Home::load_state`]).
    pub fn load(home: &Home) -> Result<Self> {
        home.load_state(&home.hosts_path(), Self::parse, |path| {
            if !path.exists() {
                return Ok(Self::default());
            }
            let text =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            Self::parse(&text, path)
        })
    }

    /// The record in `text`, read from `path` (named in errors).
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let recorded: Self = serde_json::from_str(text)
            .with_context(|| format!("parsing {}; run `openmoat init`", path.display()))?;
        if recorded.version != VERSION {
            bail!(
                "{} has version {}; this build supports {VERSION}",
                path.display(),
                recorded.version
            );
        }
        Ok(recorded)
    }

    pub fn save(&mut self, home: &Home) -> Result<()> {
        self.version = VERSION;
        let text = serde_json::to_string_pretty(self)? + "\n";
        write_private(&home.hosts_path(), text.as_bytes())
    }

    /// Whether OpenMoat created the backup at `path`.
    pub fn owns(&self, path: &Path) -> bool {
        self.backups.iter().any(|b| b == path)
    }

    pub fn dir(&self, host: Host) -> Option<PathBuf> {
        self.dirs.get(host.id()).cloned()
    }

    /// The configuration file recorded for `host` when it is not the default
    /// one in [`Self::dir`].
    pub fn file(&self, host: Host) -> Option<PathBuf> {
        self.files.get(host.id()).cloned()
    }

    /// The further directories recorded for `host` ([`Self::also`]).
    pub fn also(&self, host: Host) -> &[PathBuf] {
        self.also.get(host.id()).map_or(&[], Vec::as_slice)
    }

    /// Record `config`'s directory, its file when that is not the default,
    /// and the further directories it reads ([`also_dirs`]).
    pub fn insert(&mut self, config: &super::HostConfig) {
        let id = config.host.id().to_owned();
        let also = also_dirs(config.host, config.dir());
        if also.is_empty() {
            self.also.remove(&id);
        } else {
            self.also.insert(id.clone(), also);
        }
        self.dirs.insert(id.clone(), config.dir().to_path_buf());
        match config.custom_location() {
            Some((locate, located)) if !locate.config_is_default(&located) => {
                self.files.insert(id, located.config);
            }
            _ => {
                self.files.remove(&id);
            }
        }
    }

    /// Whether `moat init` set up other agents and left `host` out: the person
    /// said no or named other `--hosts`, so its missing hook is not a problem.
    /// An empty record (nothing set up yet, or an install from before #298)
    /// skips nothing.
    pub fn skipped(&self, host: Host) -> bool {
        !self.dirs.is_empty() && self.dir(host).is_none()
    }
}

/// The further directories `host`, whose configuration directory is `dir`,
/// reads laid out like it ([`InstallSpec::also_dirs`]) and that exist now:
/// the one a variable names, and each directory in a folder of `dir`. Never
/// the home directory, an ancestor of it or a filesystem root, which would
/// make every rule naming the configuration directory name all of them.
///
/// [`InstallSpec::also_dirs`]: openmoat_hosts::InstallSpec::also_dirs
pub fn also_dirs(host: Host, dir: &Path) -> Vec<PathBuf> {
    let Some(install) = host.spec().install.as_ref() else {
        return Vec::new();
    };
    let Ok(home) = crate::home::user_home() else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = Vec::new();
    for also in install.also_dirs {
        match also {
            AlsoDir::Variable(name) => found.extend(
                std::env::var_os(name)
                    .filter(|v| !v.is_empty())
                    .and_then(|v| crate::context::absolute(Path::new(&v)).ok()),
            ),
            AlsoDir::Below(name, child) => found.extend(
                std::env::var_os(name)
                    .filter(|v| !v.is_empty())
                    .and_then(|v| crate::context::absolute(&Path::new(&v).join(child)).ok()),
            ),
            AlsoDir::EachIn(folder) => {
                if let Ok(entries) = fs::read_dir(dir.join(folder)) {
                    found.extend(entries.filter_map(|e| Some(e.ok()?.path())));
                }
            }
        }
    }
    found.retain(|d| d.is_dir() && d != dir && crate::project::trusted(d, &home));
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests;
