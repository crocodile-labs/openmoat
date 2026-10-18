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
    /// The record in `home`; empty when `init` has not written one.
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.hosts_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let recorded: Self = serde_json::from_str(&text)
            .with_context(|| format!("parsing {}; run `moat init`", path.display()))?;
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

    /// Whether `moat init` set up other agents and left `host` out: the person
    /// said no or named other `--hosts`, so its missing hook is not a problem.
    /// An empty record (nothing set up yet, or an install from before #298)
    /// skips nothing.
    pub fn skipped(&self, host: Host) -> bool {
        !self.dirs.is_empty() && self.dir(host).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().to_path_buf());
        assert_eq!(Recorded::load(&home).unwrap(), Recorded::default());
        let mut recorded = Recorded::default();
        recorded
            .dirs
            .insert("codex".into(), PathBuf::from("/cfg/codex"));
        recorded.save(&home).unwrap();
        let loaded = Recorded::load(&home).unwrap();
        assert_eq!(loaded.dir(Host::Codex), Some(PathBuf::from("/cfg/codex")));
        assert_eq!(loaded.dir(Host::ClaudeCode), None);
        assert!(!loaded.owns(Path::new("/cfg/claude/settings.json.moat-backup")));
        fs::write(home.hosts_path(), r#"{"version":7,"dirs":{}}"#).unwrap();
        assert!(Recorded::load(&home).is_err());
    }

    #[test]
    fn skips_only_hosts_left_out_of_a_non_empty_record() {
        let mut recorded = Recorded::default();
        assert!(!recorded.skipped(Host::Codex));
        recorded
            .dirs
            .insert("claude-code".into(), PathBuf::from("/cfg/claude"));
        assert!(recorded.skipped(Host::Codex));
        assert!(!recorded.skipped(Host::ClaudeCode));
    }
}
