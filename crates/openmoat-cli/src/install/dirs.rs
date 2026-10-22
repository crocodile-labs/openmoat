//! `hosts.json`: the configuration directory of each agent `moat init` set up.
//!
//! Every later command reads the agent's files there, whatever this shell's
//! `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `CURSOR_CONFIG_DIR` say, so nobody has to
//! export them again (#298); `moat doctor` reports a variable that disagrees.
//! The lock pins the file like the policy.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::Host;
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

    /// Record `config`'s directory, and its file when that is not the default.
    pub fn insert(&mut self, config: &super::HostConfig) {
        let id = config.host.id().to_owned();
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

#[cfg(test)]
mod tests;
