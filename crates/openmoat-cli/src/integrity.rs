//! The policy lock: a pinned set of file digests the kernel refuses to run without.
//!
//! `moat init` pins the policy and every host hook file it installed. `moat guard`
//! recomputes the digests on every call and denies everything when a pinned file
//! changed or disappeared, so an agent that edits `~/.moat/policy.yaml` or removes
//! a hook gets a `deny`, not a quieter kernel. Only a human can re-pin
//! (`moat init`, or `moat doctor --accept` from a terminal). Drift of only the
//! Claude Code settings `relaxed.rs` lists, or of only the keys a host's spec
//! lists as relaxed (`spec_keys.rs`), is reported the same way, but the guard
//! keeps deciding through it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Decision, Verdict};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};
use crate::install::{HookState, HostConfig};

mod digest;
mod kept;
mod keys;
mod relaxed;
mod spec_keys;

pub use digest::sha256_hex;
use digest::{digest, digests, is_claude_settings};
pub use kept::{Kept, verify_state};
pub use relaxed::{check, split};

const LOCK_VERSION: u32 = 1;
/// Rule id of every decision the lock forces.
pub const INTEGRITY_RULE: &str = "kernel-integrity";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub version: u32,
    pub pinned_at_ms: i64,
    /// Absolute path of the `moat` binary the hooks point at.
    pub binary: String,
    /// Canonical path → lowercase hex SHA-256 of the file contents (of a Claude
    /// Code `settings.json`, without its cosmetic `theme` key; see `digest.rs`).
    pub entries: BTreeMap<String, String>,
    /// Codex `config.toml` → SHA-256 of the part OpenMoat owns (its permissions
    /// profile, ADR-018). Codex edits the rest of that file itself.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub codex_profiles: BTreeMap<String, String>,
    /// Pinned JSON or TOML file → top-level key → SHA-256 of its value, so drift
    /// can name the keys that changed. Locks written before #288 have none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, BTreeMap<String, String>>,
    /// Claude Code `settings.json` → `permissions` key → SHA-256 of its value,
    /// so the guard can tell a changed toggle from a changed hook (`relaxed.rs`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub permission_keys: BTreeMap<String, BTreeMap<String, String>>,
    /// A hook file whose host lists relaxed keys (Gemini CLI's `settings.json`)
    /// → SHA-256 of the file without them, so the guard can tell a new model
    /// or theme from any other change (`spec_keys.rs`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relaxed_rest: BTreeMap<String, String>,
    /// MCP server definitions a person accepted (`mcp/pins.rs`). `None` in a
    /// lock from before MCP pinning; their drift holds back only that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<crate::mcp::Pins>,
}

/// Which hook files a re-pin covers, besides OpenMoat's own state files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPins {
    /// `moat init`: the hook files already pinned plus every hook file installed
    /// under this shell's environment.
    Adopt,
    /// `moat allow`, `moat doctor --accept`: the hook files already pinned. The
    /// hook file an agent reads depends on the agent's environment
    /// (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`), which need not be
    /// this shell's, so a re-pin must not decide again which files those are.
    Keep,
}

/// Pin everything the kernel trusts: policy, environment snapshot, approval
/// files and the host hook files `hooks` selects. Used by `init`,
/// `doctor --accept` and `allow`, which are the only human paths that may re-pin.
pub fn repin(home: &Home, binary: &Path, hooks: HookPins) -> Result<Lock> {
    repin_with(home, binary, hooks, &[], &[])
}

/// [`repin`], also pinning `files` whole and the Codex profiles in
/// `codex_configs`: the files `moat sandbox sync` just wrote.
pub fn repin_with(
    home: &Home,
    binary: &Path,
    hooks: HookPins,
    files: &[PathBuf],
    codex_configs: &[PathBuf],
) -> Result<Lock> {
    let mut paths = state_files(home);
    paths.extend_from_slice(files);
    let mut profiles = codex_configs.to_vec();
    let lock_path = home.lock_path();
    let had_lock = lock_path.exists();
    let mut mcp_servers = None;
    if had_lock {
        match (Lock::load(&lock_path), hooks) {
            (Ok(old), _) => {
                // Only `moat mcp accept` and `moat doctor --accept` change these.
                mcp_servers = old.mcp_servers;
                paths.extend(old.entries.into_keys().map(PathBuf::from));
                profiles.extend(old.codex_profiles.into_keys().map(PathBuf::from));
            }
            (Err(e), HookPins::Keep) => {
                return Err(
                    e.context("cannot tell which hook files are pinned; run `openmoat init`")
                );
            }
            // `init` is how a person recovers from an unreadable lock.
            (Err(_), HookPins::Adopt) => {}
        }
    }
    // Without a lock there is nothing to keep, so this environment's hooks it is.
    if hooks == HookPins::Adopt || !had_lock {
        paths.extend(installed_hook_files(home, binary)?);
        profiles.extend(crate::sandbox::install::codex_profile_files(home)?);
        paths.extend(crate::sandbox::install::cursor_sandbox_files(home)?);
    }
    let mut lock = Lock::pin(binary, &paths)?;
    // A state file that is missing (one a person accepted as deleted) is
    // pinned as missing: the guard would otherwise read one planted there
    // later from disk, unpinned.
    for path in state_files(home) {
        lock.entries
            .entry(key(&path))
            .or_insert_with(|| kept::ABSENT.to_owned());
    }
    lock.mcp_servers = mcp_servers;
    for path in profiles.iter().filter(|p| p.is_file()) {
        let digest = crate::sandbox::install::codex_part_digest(path)?;
        lock.codex_profiles.insert(key(path), digest);
    }
    lock.save(&lock_path)?;
    Ok(lock)
}

/// OpenMoat's own files, pinned by every lock whatever the environment.
fn state_files(home: &Home) -> Vec<PathBuf> {
    vec![
        home.policy_path(),
        home.environment_path(),
        home.grants_path(),
        home.overlay_path(),
        home.trust_path(),
        home.hosts_path(),
    ]
}

/// The signing files only `moat policy trust-key`, `install` and `remove` pin
/// (ADR-031): the allowed signers, the pack record and each installed pack.
/// Another re-pin keeps their pins and never adds them, so a file planted
/// there is never trusted by a re-pin made for something else.
pub fn signing_files(home: &Home) -> Vec<PathBuf> {
    let mut files = vec![home.signers_path(), home.packs_path()];
    files.extend(crate::packs::installed_files(home));
    files
}

/// Hook files with a current `moat` hook under this shell's environment.
pub fn installed_hook_files(home: &Home, binary: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for host in openmoat_hosts::Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        if config.state(binary) == HookState::Installed {
            paths.extend(config.extra_files());
            paths.push(config.settings_path);
        }
    }
    Ok(paths)
}

/// How this shell's hook files differ from the ones the lock pins.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HookPinGap {
    /// Installed here but not pinned: changes to them go unseen until `moat init`.
    pub unpinned: Vec<PathBuf>,
    /// Pinned but not this shell's: another environment's hook files, still verified.
    pub elsewhere: Vec<PathBuf>,
}

impl HookPinGap {
    pub fn new(lock: &Lock, home: &Home, installed: &[PathBuf]) -> Self {
        // This shell's Cursor `sandbox.json` is pinned whole, but is no hook file.
        let mut state = state_files(home);
        state.extend(signing_files(home));
        state.extend(crate::sandbox::install::cursor_sandbox_files(home).unwrap_or_default());
        let state: Vec<String> = state.iter().map(|p| key(p)).collect();
        let here: Vec<String> = installed.iter().map(|p| key(p)).collect();
        Self {
            unpinned: installed
                .iter()
                .filter(|p| !lock.pins(p))
                .cloned()
                .collect(),
            elsewhere: lock
                .entries
                .keys()
                .filter(|k| !state.contains(k) && !here.contains(k))
                .map(PathBuf::from)
                .collect(),
        }
    }

    /// Why a pinned hook file may not be this shell's: one of the variables
    /// that move a host's directory differs. Every host's is named.
    pub fn moved_by() -> String {
        let names: Vec<&str> = openmoat_hosts::Host::ALL
            .iter()
            .filter_map(|host| host.spec().install.as_ref())
            .map(|install| install.dir_variable)
            .collect();
        format!("one of {} differs", names.join(", "))
    }
}

/// `Some(deny)` when the pinned policy or hook files changed since `moat init`.
pub fn violation(home: &Home) -> Result<Option<Decision>> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!(
            "no policy lock at {}; run `openmoat init`",
            lock_path.display()
        );
    }
    Ok(deny_for(&Lock::load(&lock_path)?.verify()))
}

/// The `kernel-integrity` deny naming `drift`; `None` when there is none.
fn deny_for(drift: &[Drift]) -> Option<Decision> {
    if drift.is_empty() {
        return None;
    }
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(d.to_string());
    }
    decision.reasons.push(
        "run `openmoat doctor` to inspect; `openmoat doctor --accept` or `openmoat init` to re-pin"
            .to_owned(),
    );
    Some(decision)
}

/// Refuse a person's command that re-pins while pinned files drifted: the
/// re-pin would accept a tampered file unseen. `doing` completes "refusing to …".
pub fn refuse_drift(home: &Home, doing: &str) -> Result<()> {
    if let Some(deny) = violation(home)? {
        bail!(
            "refusing to {doing} while the policy lock shows drift ({INTEGRITY_RULE}):\n  {}",
            deny.reasons.join("\n  ")
        );
    }
    Ok(())
}

/// Forget the pins of `paths`, the host files `moat uninstall` just undid, and
/// pin `rewritten` whole, the files a person's command just wrote (`hosts.json`,
/// or a pinned file `moat mcp wrap` changed). Every other pin stays as it is,
/// so no drift elsewhere is accepted.
pub fn unpin(home: &Home, paths: &[PathBuf], rewritten: &[PathBuf]) -> Result<()> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        return Ok(());
    }
    let mut lock = Lock::load(&lock_path)?;
    for path in paths.iter().map(|p| key(p)) {
        lock.codex_profiles.remove(&path);
    }
    for path in paths.iter().chain(rewritten).map(|p| key(p)) {
        lock.entries.remove(&path);
        lock.keys.remove(&path);
        lock.permission_keys.remove(&path);
        lock.relaxed_rest.remove(&path);
    }
    let fresh = Lock::pin(Path::new(&lock.binary), rewritten)?;
    lock.entries.extend(fresh.entries);
    lock.keys.extend(fresh.keys);
    lock.permission_keys.extend(fresh.permission_keys);
    lock.relaxed_rest.extend(fresh.relaxed_rest);
    lock.save(&lock_path)
}

/// One way a pinned file differs from the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    Modified(PathBuf),
    /// Modified, with the top-level keys that differ from the pin.
    KeysChanged(PathBuf, String),
    Missing(PathBuf),
    Unreadable(PathBuf, String),
    /// A staged copy (`proposal`) that would change the pinned `target`.
    Proposed {
        proposal: PathBuf,
        target: PathBuf,
    },
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Modified(p) => write!(f, "{} was modified", p.display()),
            Self::KeysChanged(p, keys) => write!(f, "{} was modified: {keys}", p.display()),
            Self::Missing(p) => write!(f, "{} is missing", p.display()),
            Self::Unreadable(p, why) => write!(f, "{} is unreadable: {why}", p.display()),
            Self::Proposed { proposal, target } => write!(
                f,
                "{} would change {}",
                proposal.display(),
                target.display()
            ),
        }
    }
}

impl Lock {
    /// Pin the current contents of `paths`. Files that do not exist are skipped;
    /// callers pass only files they just wrote or verified.
    pub fn pin(binary: &Path, paths: &[PathBuf]) -> Result<Self> {
        let (mut entries, mut keys, mut permission_keys, mut relaxed_rest) = (
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        for path in paths {
            if path.is_file() {
                entries.insert(key(path), digest(path, is_claude_settings(path))?);
                if let Some(digests) = keys::key_digests(path) {
                    keys.insert(key(path), digests);
                }
                if let Some(digests) = relaxed::permission_digests(path) {
                    permission_keys.insert(key(path), digests);
                }
                if let Some(rest) = spec_keys::pinned_rest(path) {
                    relaxed_rest.insert(key(path), rest);
                }
            }
        }
        Ok(Self {
            version: LOCK_VERSION,
            pinned_at_ms: crate::time::now_ms(),
            binary: binary.to_string_lossy().into_owned(),
            entries,
            codex_profiles: BTreeMap::new(),
            keys,
            permission_keys,
            relaxed_rest,
            mcp_servers: None,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading lock {}", path.display()))?;
        Self::parse(&bytes, path)
    }

    /// The lock in `bytes`, read from `path` (named in errors).
    pub fn parse(bytes: &[u8], path: &Path) -> Result<Self> {
        let lock: Self = serde_json::from_slice(bytes)
            .with_context(|| format!("parsing lock {}", path.display()))?;
        if lock.version != LOCK_VERSION {
            bail!(
                "lock {} has version {}; this build supports {LOCK_VERSION}",
                path.display(),
                lock.version
            );
        }
        Ok(lock)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        write_private(path, text.as_bytes())
    }

    /// Compare pinned digests with the files on disk. Empty means intact.
    pub fn verify(&self) -> Vec<Drift> {
        self.verify_keeping(&[], &[]).0
    }

    /// Whether the lock pins the moat profile in the Codex config at `path`.
    pub fn pins_codex_profile(&self, path: &Path) -> bool {
        self.codex_profiles.contains_key(&key(path))
    }

    /// Drift for one pinned file, or `None` when it is intact or not pinned.
    pub fn verify_one(&self, path: &Path) -> Option<Drift> {
        let expected = self.entries.get(&key(path))?;
        self.check_one(&PathBuf::from(key(path)), expected)
            .err()
            .map(|(drift, _)| drift)
    }

    /// Drift that renaming `proposal` over the pinned `target` would leave: the
    /// target's own drift, else any difference between the proposal and the
    /// pinned contents. `None` when the target is not pinned.
    pub fn verify_proposal(&self, proposal: &Path, target: &Path) -> Option<Drift> {
        let expected = self.entries.get(&key(target))?;
        if let Some(drift) = self.verify_one(target) {
            return Some(drift);
        }
        match digests(proposal, is_claude_settings(target)) {
            Ok(actual) if actual.contains(expected) => None,
            Ok(_) => Some(Drift::Proposed {
                proposal: proposal.to_path_buf(),
                target: PathBuf::from(key(target)),
            }),
            Err(e) => Some(Drift::Unreadable(proposal.to_path_buf(), format!("{e:#}"))),
        }
    }

    pub fn pins(&self, path: &Path) -> bool {
        self.entries.contains_key(&key(path))
    }
}

/// Identity of a pinned file: its canonical directory plus its own name. The
/// leaf is deliberately not resolved, so a file that is later replaced by a
/// symlink keeps the same key and is compared, not forgotten. The parent is
/// canonicalised so `/var/...` and `/private/var/...` agree on macOS and a
/// deleted file still has a key.
fn key(path: &Path) -> String {
    let located = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |p| p.join(name))
        }
        _ => path.to_path_buf(),
    };
    let text = located.to_string_lossy();
    if cfg!(windows) {
        crate::context::strip_verbatim(&text)
    } else {
        text.into_owned()
    }
}

#[cfg(test)]
mod tests;
