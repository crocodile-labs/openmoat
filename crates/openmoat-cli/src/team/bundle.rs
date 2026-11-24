//! A team bundle as a team publishes it (ADR-119): a folder (in a repository
//! clone or a path an MDM tool keeps) holding a manifest, its OpenSSH
//! signature, and the rule files the manifest names with their SHA-256. One
//! signature covers everything: the manifest commits to each file's digest.
//!
//! ```text
//! openmoat-team.yaml        format, name, serial, policy, packs, settings, require_hooks
//! openmoat-team.yaml.sig    ssh-keygen -Y sign -n openmoat-team-bundle
//! policy.yaml               the team's rules (repository-policy shape, no allow)
//! packs/<name>.yaml         more rule files of the same shape
//! ```

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::RepoPolicy;
use openmoat_hosts::Host;
use serde::{Deserialize, Serialize};

use super::settings::Settings;
use crate::home::{Home, create_private_dir, write_private};
use crate::integrity::sha256_hex;
use crate::signing::{self, Signed};

/// The manifest's `format`; a new manifest shape gets a new value.
pub const FORMAT: &str = "openmoat-team-bundle-v1";
/// The manifest's file name in the bundle's folder.
pub const MANIFEST: &str = "openmoat-team.yaml";
/// Its signature's file name.
pub const SIGNATURE: &str = "openmoat-team.yaml.sig";
/// The name the manifest's `policy:` file has among the rule files.
pub const POLICY_NAME: &str = "policy";

/// Most rule files one bundle names.
const MAX_FILES: usize = 32;
/// Largest manifest, signature or rule file read.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// The manifest, `openmoat-team.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: String,
    /// The team's name: lowercase letters, digits, `-` and `_`.
    pub name: String,
    /// Raised with every bundle the team publishes: an update to a lower one
    /// is refused, so an old bundle cannot be replayed to undo a newer rule.
    pub serial: u64,
    /// The team's main rule file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<FileRef>,
    /// More rule files, each by its own name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackRef>,
    /// The settings it requires.
    #[serde(default)]
    pub settings: Settings,
    /// Agents, by id, whose OpenMoat hook must be installed and running on
    /// every machine (`openmoat inventory --check`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_hooks: Vec<String>,
}

/// A rule file of the bundle and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    /// Relative to the bundle's folder, `/`-separated, no `..`.
    pub path: String,
    /// Lowercase hex.
    pub sha256: String,
}

/// A named rule file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRef {
    /// Lowercase letters, digits, `-` and `_`; not [`POLICY_NAME`].
    pub name: String,
    /// Relative to the bundle's folder.
    pub path: String,
    /// Lowercase hex.
    pub sha256: String,
}

impl Manifest {
    /// Parse and check the manifest's text.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Self = openmoat_core::yaml::from_str(text)
            .with_context(|| format!("not a team bundle manifest ({MANIFEST})"))?;
        ensure!(
            manifest.format == FORMAT,
            "{MANIFEST}: format is `{}`; this build reads `{FORMAT}`",
            manifest.format
        );
        crate::packs::check_name(&manifest.name).context("the team's name")?;
        ensure!(manifest.serial >= 1, "{MANIFEST}: serial starts at 1");
        let files = manifest.files();
        ensure!(
            files.len() <= MAX_FILES,
            "{MANIFEST}: at most {MAX_FILES} rule files"
        );
        for (n, (name, path, sha)) in files.iter().enumerate() {
            crate::packs::check_name(name)?;
            ensure!(
                (n == 0 && manifest.policy.is_some()) || *name != POLICY_NAME,
                "pack name `{POLICY_NAME}` is the `policy:` file's"
            );
            ensure!(
                !files[..n].iter().any(|(other, _, _)| other == name),
                "two rule files are named `{name}`"
            );
            check_path(path)?;
            ensure!(
                sha.len() == 64
                    && sha
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "`{path}`: sha256 must be 64 lowercase hex digits"
            );
        }
        manifest.settings.check()?;
        manifest.hooks()?;
        Ok(manifest)
    }

    /// Every rule file as `(name, path, sha256)`, the `policy:` one first.
    pub fn files(&self) -> Vec<(&str, &str, &str)> {
        let policy = self
            .policy
            .iter()
            .map(|f| (POLICY_NAME, f.path.as_str(), f.sha256.as_str()));
        let packs = self
            .packs
            .iter()
            .map(|p| (p.name.as_str(), p.path.as_str(), p.sha256.as_str()));
        policy.chain(packs).collect()
    }

    /// The agents `require_hooks` names; an error for an id no installable
    /// agent has.
    pub fn hooks(&self) -> Result<Vec<Host>> {
        self.require_hooks
            .iter()
            .map(|id| {
                Host::from_str(id)
                    .ok()
                    .filter(|host| Host::ALL.contains(host))
                    .with_context(|| {
                        format!("require_hooks: `{id}` is not an agent OpenMoat hooks")
                    })
            })
            .collect()
    }
}

/// A path inside the bundle's folder: relative, `/`-separated, plain names.
fn check_path(path: &str) -> Result<()> {
    let plain = !path.is_empty()
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
    ensure!(
        plain && Path::new(path).extension().is_some_and(|e| e == "yaml"),
        "`{path}` must be a relative `.yaml` path inside the bundle's folder, without `..`"
    );
    Ok(())
}

/// One rule file, read and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFile {
    /// Its name in the manifest.
    pub name: String,
    /// The bytes that matched the manifest's digest.
    pub text: String,
    /// Its rules.
    pub rules: RepoPolicy,
}

/// A bundle whose signature verified and whose files match the manifest.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub manifest: Manifest,
    /// The manifest's bytes, as verified.
    pub manifest_bytes: Vec<u8>,
    /// The signature's bytes.
    pub signature: Vec<u8>,
    /// The rule files in [`Manifest::files`] order.
    pub files: Vec<RuleFile>,
    /// The allowed-signers principal whose key signed the manifest.
    pub signer: String,
}

impl Bundle {
    /// The SHA-256 of the manifest's bytes: the whole bundle's identity.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(&self.manifest_bytes)
    }
}

/// A rule file's text as a team layer takes it: a repository policy's
/// shape, without allow rules, which would widen the person's policy.
pub fn parse_rules(name: &str, text: &str) -> Result<RepoPolicy> {
    let rules = crate::packs::parse(text).with_context(|| format!("rule file `{name}`"))?;
    if let Some(group) = rules.allow.first() {
        bail!(
            "rule file `{name}`: allow rule `{}`: a team bundle only narrows; allow rules \
             belong in a person's own policy or a pack they install",
            group.id
        );
    }
    Ok(rules)
}

/// Read the bundle in `dir`, verify its manifest's signature against the
/// allowed-signers file `signers` and each file against the manifest.
pub fn verify(home: &Home, signers: &Path, dir: &Path) -> Result<Bundle> {
    let program = signing::require(home)?;
    let dir = fs::canonicalize(dir).with_context(|| format!("reading {}", dir.display()))?;
    ensure!(dir.is_dir(), "{} is not a folder", dir.display());
    let manifest_bytes = read_inside(&dir, MANIFEST)?;
    let signature = read_inside(&dir, SIGNATURE)?;
    // The bytes that verify are the bytes installed: `ssh-keygen` reads the
    // signature from a file, so it gets a private copy of these bytes.
    create_private_dir(&home.team_dir())?;
    let staged = home
        .team_dir()
        .join(format!(".staged.{}.sig", std::process::id()));
    write_private(&staged, &signature)?;
    let signer = signing::verify(
        &program,
        signers,
        &manifest_bytes,
        &staged,
        Signed::TeamBundle,
    );
    let _ = fs::remove_file(&staged);
    let Some(signer) = signer? else {
        bail!(
            "refusing the bundle in {}: {SIGNATURE} does not verify against the team's key \
             (sign {MANIFEST} with `ssh-keygen -Y sign -n {}`)",
            dir.display(),
            signing::TEAM_NAMESPACE
        );
    };
    let text = std::str::from_utf8(&manifest_bytes).context("the manifest must be UTF-8")?;
    let manifest = Manifest::parse(text)?;
    let mut files = Vec::new();
    for (name, path, sha) in manifest.files() {
        let bytes = read_inside(&dir, path)?;
        ensure!(
            sha256_hex(&bytes) == sha,
            "`{path}` does not match the digest {MANIFEST} gives it: the bundle changed after it \
             was signed"
        );
        let text = String::from_utf8(bytes).with_context(|| format!("`{path}` must be UTF-8"))?;
        let rules = parse_rules(name, &text)?;
        files.push(RuleFile {
            name: name.to_owned(),
            text,
            rules,
        });
    }
    Ok(Bundle {
        manifest,
        manifest_bytes,
        signature,
        files,
        signer,
    })
}

/// The regular file `rel` inside `dir` (canonical): no link out of the
/// folder, no FIFO that would hold the command, nothing over the size cap.
fn read_inside(dir: &Path, rel: &str) -> Result<Vec<u8>> {
    let path: PathBuf = dir.join(rel);
    let meta =
        fs::symlink_metadata(&path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        meta.file_type().is_file(),
        "{} is not a regular file",
        path.display()
    );
    ensure!(
        meta.len() <= MAX_FILE_BYTES,
        "{} is larger than {MAX_FILE_BYTES} bytes",
        path.display()
    );
    let resolved =
        fs::canonicalize(&path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        resolved.starts_with(dir),
        "{} is outside the bundle's folder",
        path.display()
    );
    fs::read(&resolved).with_context(|| format!("reading {}", path.display()))
}
