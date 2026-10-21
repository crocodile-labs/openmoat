//! Policy packs (ADR-031): a team's rules a person installs with `moat policy
//! install` after their signature verified against a trusted key.
//!
//! An installed pack is a copy of the exact bytes that verified, with its
//! signature, under `~/.moat/policy.d/packs/`, recorded with its SHA-256 and
//! signer in `~/.moat/packs.json`. All three are pinned by the lock, so a pack
//! changed after install is drift and the guard denies. A pack has the shape of
//! a repository policy (only `version`, `deny`, `ask`, `allow`) and merges like
//! a trusted one: its rule ids get the `pack:<name>:` prefix, its deny rules join
//! the user's, its ask rules are tried before the user's allow rules, and its
//! allow rules widen the policy, never past a deny.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Policy, RepoPolicy, RuleGroup};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};
use crate::integrity::{Lock, sha256_hex};

/// Prefix of every rule id a pack contributes, before the pack's name.
pub const PACK_RULE_PREFIX: &str = "pack:";

const PACKS_VERSION: u32 = 1;

/// `~/.moat/packs.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packs {
    pub version: u32,
    /// Pack name → how it was installed.
    pub packs: BTreeMap<String, Installed>,
}

/// One installed pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    /// Lowercase hex SHA-256 of the pack's bytes, as verified.
    pub sha256: String,
    /// The allowed-signers principal whose key signed it.
    pub signer: String,
    /// When `moat policy install` installed it (ms since the epoch).
    pub at_ms: i64,
}

impl Default for Packs {
    fn default() -> Self {
        Self {
            version: PACKS_VERSION,
            packs: BTreeMap::new(),
        }
    }
}

impl Packs {
    /// A missing file is no packs; a malformed or newer one is an error.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// The pack record in `text`, read from `path` (named in errors).
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let packs: Self =
            serde_json::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
        if packs.version != PACKS_VERSION {
            bail!(
                "{} has version {}; this build supports {PACKS_VERSION}",
                path.display(),
                packs.version
            );
        }
        if let Some(bad) = packs.packs.keys().find(|n| check_name(n).is_err()) {
            bail!("{}: `{bad}` is not a pack name", path.display());
        }
        Ok(packs)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }
}

/// A pack name: lowercase letters, digits, `-` and `_`, as a file name and a
/// rule id prefix take it.
pub fn check_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !valid {
        bail!("`{name}` is not a pack name: use lowercase letters, digits, `-` and `_`");
    }
    Ok(())
}

/// The installed copy of pack `name`.
pub fn pack_path(home: &Home, name: &str) -> PathBuf {
    home.packs_dir().join(format!("{name}.yaml"))
}

/// The installed copy of pack `name`'s signature.
pub fn sig_path(home: &Home, name: &str) -> PathBuf {
    home.packs_dir().join(format!("{name}.yaml.sig"))
}

/// Every installed pack and signature file, for the lock to pin.
pub fn installed_files(home: &Home) -> Vec<PathBuf> {
    Packs::load(&home.packs_path())
        .map(|packs| {
            packs
                .packs
                .keys()
                .flat_map(|name| [pack_path(home, name), sig_path(home, name)])
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a pack's text: a repository policy's shape, linted the same way.
pub fn parse(text: &str) -> Result<RepoPolicy> {
    RepoPolicy::parse(text)
        .context("not a policy pack: a pack holds only `version`, `deny`, `ask` and `allow` rules")
}

/// `policy` with `pack`'s rules merged in under `pack:<name>:` ids.
pub fn apply(policy: &mut Policy, name: &str, pack: &RepoPolicy) -> Result<()> {
    let prefixed = |groups: &[RuleGroup]| -> Vec<RuleGroup> {
        groups
            .iter()
            .map(|g| RuleGroup {
                id: format!("{PACK_RULE_PREFIX}{name}:{}", g.id),
                ..g.clone()
            })
            .collect()
    };
    policy.deny.extend(prefixed(&pack.deny));
    policy.repo_ask.extend(prefixed(&pack.ask));
    policy.allow.extend(prefixed(&pack.allow));
    policy
        .lint()
        .with_context(|| format!("merging policy pack `{name}`"))
}

/// Merge every installed pack into `policy`. Only a `packs.json` the lock pins
/// counts (`moat policy install` re-pins after writing it), and each pack must
/// still have the digest it was installed with. Bytes the lock check kept
/// ([`Home::load_state`]) are of a pinned file, as it matched its pin.
pub fn merge_installed(home: &Home, policy: &mut Policy) -> Result<()> {
    let path = home.packs_path();
    let from_disk = |path: &Path| {
        if !path.is_file() || !Lock::load(&home.lock_path()).is_ok_and(|lock| lock.pins(path)) {
            return Ok(None);
        }
        Packs::load(path).map(Some)
    };
    let Some(packs) = home.load_state(
        &path,
        |text, path| Packs::parse(text, path).map(Some),
        from_disk,
    )?
    else {
        return Ok(());
    };
    for (name, record) in packs.packs {
        let file = pack_path(home, &name);
        let text = match home.kept().get(&file) {
            Some(bytes) => String::from_utf8(bytes.to_vec()).map_err(anyhow::Error::from),
            None => fs::read_to_string(&file).map_err(anyhow::Error::from),
        }
        .with_context(|| format!("reading policy pack {}", file.display()))?;
        if sha256_hex(text.as_bytes()) != record.sha256 {
            bail!(
                "policy pack {} changed since `openmoat policy install`; reinstall it",
                file.display()
            );
        }
        let pack = parse(&text).with_context(|| format!("policy pack {}", file.display()))?;
        apply(policy, &name, &pack)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
