//! `~/.moat/trust.json`: the repository policies a person accepted with
//! `moat trust` (ADR-022), each bound to its project root and the SHA-256 of
//! the exact file. Pinned by the policy lock like the approval files.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::home::write_private;

const TRUST_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    pub version: u32,
    /// Canonical project root → lowercase hex SHA-256 of its trusted policy file.
    pub repos: BTreeMap<String, String>,
}

impl Default for Trust {
    fn default() -> Self {
        Self {
            version: TRUST_VERSION,
            repos: BTreeMap::new(),
        }
    }
}

impl Trust {
    /// Missing file means nothing is trusted; a malformed or newer file is an error.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// The trust records in `text`, read from `path` (named in errors).
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let trust: Self =
            serde_json::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
        if trust.version != TRUST_VERSION {
            bail!(
                "{} has version {}; this build supports {TRUST_VERSION}",
                path.display(),
                trust.version
            );
        }
        Ok(trust)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }

    /// Whether the file with `digest` at project `root` is the one a person trusted.
    #[must_use]
    pub fn trusts(&self, root: &str, digest: &str) -> bool {
        self.repos.get(root).is_some_and(|d| d == digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_is_bound_to_root_and_digest_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        assert_eq!(Trust::load(&path).unwrap(), Trust::default());

        let mut t = Trust::default();
        t.repos.insert("/code/app".into(), "aa".into());
        t.save(&path).unwrap();
        let loaded = Trust::load(&path).unwrap();
        assert!(loaded.trusts("/code/app", "aa"));
        assert!(!loaded.trusts("/code/app", "bb"), "a changed file");
        assert!(
            !loaded.trusts("/code/fork", "aa"),
            "the same file elsewhere"
        );

        fs::write(&path, r#"{"version":2,"repos":{}}"#).unwrap();
        assert!(
            Trust::load(&path)
                .unwrap_err()
                .to_string()
                .contains("version 2")
        );
    }
}
