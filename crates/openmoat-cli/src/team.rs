//! Team mode without a hosted service (ADR-119): a signed bundle a team
//! publishes in a repository or an MDM-managed folder, installed by a person
//! with `openmoat team join` as a managed layer over their own policy.
//!
//! The layer only narrows. Its rule files have a repository policy's shape
//! without allow rules: deny rules join the person's (absolute, ADR-002),
//! review rules are tried before the person's allow rules (as a repository
//! policy's are, ADR-022), `require:` levels only raise (ADR-064) and
//! `requests:` deny lists only narrow (ADR-062). Its settings raise the
//! person's to the stricter value ([`settings`]). So nothing in the person's
//! own policy can widen past the team's, and the team can widen nothing on
//! the person's machine.
//!
//! What is installed is a copy of the exact bytes that verified: the manifest,
//! its signature and each rule file under `~/.moat/team/`, with the team's
//! signing key (`allowed_signers`, for [`TEAM_NAMESPACE`] only) and the record
//! `~/.moat/team.json`. All of them are pinned by the lock, so a change after
//! `team join` or `team update` is drift, and the guard denies. Only a
//! `team.json` the lock pins counts, as for packs.
//!
//! [`TEAM_NAMESPACE`]: crate::signing::TEAM_NAMESPACE

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Policy, RequiredBy, RuleGroup};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};
use crate::integrity::{Lock, sha256_hex};

pub mod bundle;
pub mod settings;
#[cfg(test)]
mod tests;

pub use bundle::{Bundle, Manifest, RuleFile};

/// Prefix of every rule id the team layer contributes, before the team's
/// name and the rule file's: `team:<team>:<file>:<id>`.
pub const TEAM_RULE_PREFIX: &str = "team:";

const RECORD_VERSION: u32 = 1;

/// Which team layer a policy load merges in.
#[derive(Debug, Clone, Copy)]
pub enum Layer<'a> {
    /// The joined team's, as installed: what the guard decides by.
    Joined,
    /// None: the person's policy alone, to compare a change with.
    None,
    /// This bundle's, in place of the joined one, to compare a change with.
    This(&'a Bundle),
}

/// `~/.moat/team.json`: the joined team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Joined {
    pub version: u32,
    /// The team's name in its manifest.
    pub name: String,
    /// The installed bundle's serial.
    pub serial: u64,
    /// The allowed-signers principal whose key signed it.
    pub signer: String,
    /// SHA-256 of the installed manifest.
    pub manifest_sha256: String,
    /// The folder it was joined or last updated from, which `team update`
    /// reads again unless given another.
    pub source: String,
    /// When it was joined or last updated (ms since the epoch).
    pub at_ms: i64,
}

impl Joined {
    /// The record of `bundle`, read from `source`.
    #[must_use]
    pub fn of(bundle: &Bundle, source: &Path) -> Self {
        Self {
            version: RECORD_VERSION,
            name: bundle.manifest.name.clone(),
            serial: bundle.manifest.serial,
            signer: bundle.signer.clone(),
            manifest_sha256: bundle.digest(),
            source: source.to_string_lossy().into_owned(),
            at_ms: crate::time::now_ms(),
        }
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let joined: Self =
            serde_json::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
        if joined.version != RECORD_VERSION {
            bail!(
                "{} has version {}; this build supports {RECORD_VERSION}",
                path.display(),
                joined.version
            );
        }
        crate::packs::check_name(&joined.name)?;
        Ok(joined)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }
}

/// The joined team, when the lock pins its record; from the bytes the lock
/// check kept when it kept them.
pub fn joined(home: &Home) -> Result<Option<Joined>> {
    let path = home.team_path();
    let from_disk = |path: &Path| {
        if !path.is_file() || !Lock::load(&home.lock_path()).is_ok_and(|lock| lock.pins(path)) {
            return Ok(None);
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Joined::parse(&text, path).map(Some)
    };
    home.load_state(
        &path,
        |text, path| Joined::parse(text, path).map(Some),
        from_disk,
    )
}

/// The installed manifest.
pub fn manifest_path(home: &Home) -> PathBuf {
    home.team_dir().join(bundle::MANIFEST)
}

/// The installed manifest's signature.
pub fn signature_path(home: &Home) -> PathBuf {
    home.team_dir().join(bundle::SIGNATURE)
}

/// The team's signing key, for its bundles' namespace only.
pub fn signers_path(home: &Home) -> PathBuf {
    home.team_dir().join("allowed_signers")
}

/// Where the installed rule files are.
pub fn rules_dir(home: &Home) -> PathBuf {
    home.team_dir().join("rules")
}

/// The installed copy of rule file `name`.
pub fn rule_path(home: &Home, name: &str) -> PathBuf {
    rules_dir(home).join(format!("{name}.yaml"))
}

/// The team's signing key, when the lock pins it: one written by anyone but
/// `openmoat team join` is not trusted.
pub fn trusted_signers(home: &Home) -> Option<PathBuf> {
    let path = signers_path(home);
    let lock = Lock::load(&home.lock_path()).ok()?;
    (path.is_file() && lock.pins(&path)).then_some(path)
}

/// Every installed team file, for the lock to pin; none when no team is
/// joined. The record itself is a state file ([`Home::team_path`]).
pub fn installed_files(home: &Home) -> Vec<PathBuf> {
    let path = home.team_path();
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(joined) = Joined::parse(&text, &path) else {
        return Vec::new();
    };
    let mut files = vec![
        manifest_path(home),
        signature_path(home),
        signers_path(home),
    ];
    if let Ok(text) = fs::read_to_string(manifest_path(home))
        && sha256_hex(text.as_bytes()) == joined.manifest_sha256
        && let Ok(manifest) = Manifest::parse(&text)
    {
        files.extend(
            manifest
                .files()
                .into_iter()
                .map(|(name, _, _)| rule_path(home, name)),
        );
    }
    files
}

/// `policy` with the team `layer` merged in.
pub fn merge(home: &Home, policy: &mut Policy, layer: Layer<'_>) -> Result<()> {
    match layer {
        Layer::None => Ok(()),
        Layer::This(bundle) => apply(policy, &bundle.manifest, &bundle.files),
        Layer::Joined => {
            let Some(joined) = joined(home)? else {
                return Ok(());
            };
            let (manifest, files) = installed(home, &joined)?;
            apply(policy, &manifest, &files)
        }
    }
}

/// The installed bundle of `joined`, each file checked against its digest.
pub fn installed(home: &Home, joined: &Joined) -> Result<(Manifest, Vec<RuleFile>)> {
    let changed = |path: &Path| {
        format!(
            "the team bundle's {} changed since `openmoat team join`; run `openmoat team update` \
             from your terminal",
            path.display()
        )
    };
    let path = manifest_path(home);
    let text = installed_text(home, &path)?;
    if sha256_hex(text.as_bytes()) != joined.manifest_sha256 {
        bail!(changed(&path));
    }
    let manifest = Manifest::parse(&text)?;
    let mut files = Vec::new();
    for (name, _, sha) in manifest.files() {
        let path = rule_path(home, name);
        let text = installed_text(home, &path)?;
        if sha256_hex(text.as_bytes()) != sha {
            bail!(changed(&path));
        }
        let rules = bundle::parse_rules(name, &text)?;
        files.push(RuleFile {
            name: name.to_owned(),
            text,
            rules,
        });
    }
    Ok((manifest, files))
}

/// An installed file's text: the bytes the lock check kept, else from disk.
fn installed_text(home: &Home, path: &Path) -> Result<String> {
    match home.kept().get(path) {
        Some(bytes) => String::from_utf8(bytes.to_vec()).map_err(anyhow::Error::from),
        None => fs::read_to_string(path).map_err(anyhow::Error::from),
    }
    .with_context(|| format!("reading {}", path.display()))
}

/// `policy` with the team's rules under `team:<team>:<file>:` ids and its
/// settings applied. Deny and review rules only: [`bundle::parse_rules`]
/// refused allow rules, and none is merged whatever the file says.
pub fn apply(policy: &mut Policy, manifest: &Manifest, files: &[RuleFile]) -> Result<()> {
    let team = &manifest.name;
    for file in files {
        let prefix = format!("{TEAM_RULE_PREFIX}{team}:{}:", file.name);
        let prefixed = |groups: &[RuleGroup]| -> Vec<RuleGroup> {
            groups
                .iter()
                .map(|g| RuleGroup {
                    id: format!("{prefix}{}", g.id),
                    ..g.clone()
                })
                .collect()
        };
        policy.deny.extend(prefixed(&file.rules.deny));
        policy.repo_review.extend(prefixed(&file.rules.review));
        file.rules.add_requests(policy, &prefix);
        if let Some(require) = &file.rules.require {
            policy.add_requirement(
                RequiredBy::Pack(format!("{TEAM_RULE_PREFIX}{team}")),
                require,
            );
        }
        file.rules
            .deny
            .iter()
            .chain(&file.rules.review)
            .try_for_each(RuleGroup::check_patterns)
            .and_then(|()| policy.lint_structure())
            .with_context(|| format!("merging the team bundle's rule file `{}`", file.name))?;
    }
    manifest.settings.apply(policy);
    Ok(())
}
