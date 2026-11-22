//! The audit log's checkpoint signing key, `~/.moat/audit.key.ed25519`, and the
//! signed checkpoints kept in `~/.moat/checkpoints/` (ADR-110).
//!
//! The key is an Ed25519 seed, separate from the audit key (ADR-101): the
//! audit key's MACs can be checked only by whoever holds it, the checkpoints by
//! anyone with the public key, which `openmoat doctor` shows. It is kept as the
//! audit key is: written once, owner-only, through a temporary
//! `audit.key.ed25519.<pid>.<nanos>.tmp`, refused when others may read it
//! (`key_file::read`), and denied to agents by `kernel-self`'s `audit.key*`,
//! which covers the key, its temporary file and keys kept after a rotation.
//!
//! A person's `openmoat init`, `openmoat audit anchor` and `openmoat audit
//! checkpoint` make it when it is missing; no other writer does, so a log
//! without one (an older install) keeps recording as before and only has no
//! checkpoints. The guard signs one every [`EVERY`] events when the key is
//! there, best effort: a checkpoint that cannot be made never fails a call.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use openmoat_audit::{Checkpoint, EventId, Frontier, SigningKey, Store, VerifierKey};
use zeroize::Zeroizing;

use crate::home::Home;

/// The signing key file in OpenMoat's state directory. Its name starts with
/// the audit key's, so `kernel-self`'s `audit.key*` denies it to agents.
pub const KEY_FILE: &str = "audit.key.ed25519";

/// The folder the signed checkpoints are written to.
const DIR: &str = "checkpoints";

/// Where the guard's next checkpoint starts from: the Merkle frontier.
const FRONTIER: &str = "frontier";

/// The guard signs a checkpoint at each event whose id is a multiple of this.
pub const EVERY: i64 = 1000;

/// Where the signing key of `home` is.
pub fn path(home: &Home) -> PathBuf {
    home.root().join(KEY_FILE)
}

/// Where the checkpoints of `home` are written.
pub fn dir(home: &Home) -> PathBuf {
    home.root().join(DIR)
}

/// The signing key of `home`: `None` when there is none, an error when it is
/// there but cannot be used. The error names the file, never its contents.
pub fn read(home: &Home) -> Result<Option<SigningKey>> {
    let path = path(home);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let text = crate::key_file::read(&path)?;
    let key = SigningKey::parse(&text).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(key))
}

/// The signing key of `home`, made when there is none (a person's command
/// only); whether it was made now.
pub fn ensure(home: &Home) -> Result<(SigningKey, bool)> {
    if let Some(key) = read(home)? {
        return Ok((key, false));
    }
    let made = make(home)?;
    Ok((made, true))
}

fn make(home: &Home) -> Result<SigningKey> {
    let path = path(home);
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice())
        .map_err(|e| anyhow::Error::msg(e.to_string()))
        .context("reading random bytes for the audit signing key")?;
    let key = SigningKey::from_seed(&seed)?;
    // Two people's commands making it at once: the first file is kept.
    crate::home::write_private_new(&path, key.encode().as_bytes())?;
    read(home)?.with_context(|| format!("{} is gone just after it was made", path.display()))
}

/// Start a new signing key, keeping the one it replaces as
/// `audit.key.ed25519.<ms>.old` (owner-only): checkpoints it signed still
/// verify with its public key, which the caller should keep. Where the old
/// key went, if there was one.
pub fn rotate(home: &Home) -> Result<(SigningKey, Option<PathBuf>)> {
    let old = path(home);
    let mut kept = None;
    if std::fs::symlink_metadata(&old).is_ok() {
        let to = home
            .root()
            .join(format!("{KEY_FILE}.{}.old", crate::time::now_ms()));
        crate::home::keep_private(&old, &to)?;
        kept = Some(to);
    }
    // The frontier is the log's, not the key's: the new key's first
    // checkpoint states the same events the old key's last one did.
    Ok((make(home)?, kept))
}

/// A checkpoint written to the checkpoint folder.
pub struct Written {
    /// Where.
    pub path: PathBuf,
    /// The signed note.
    pub note: String,
    /// What it states.
    pub checkpoint: Checkpoint,
}

/// Sign a checkpoint over every chained event of `store` now, reading the log
/// from its first event, and keep it with the frontier for the guard's next.
pub fn sign_now(home: &Home, store: &Store, key: &SigningKey) -> Result<Written> {
    let frontier = store.frontier()?;
    write(home, &frontier, key)
}

/// The guard's checkpoint after recording event `id`: only at every
/// [`EVERY`]th event and when the key is there, from the saved frontier.
/// Best effort: any failure leaves the call as decided and is not reported,
/// since `openmoat doctor` shows how far behind the newest checkpoint is.
pub fn periodic(home: &Home, store: &Store, id: EventId) {
    if id.0 <= 0 || id.0 % EVERY != 0 {
        return;
    }
    let _ = (|| -> Result<()> {
        let Some(key) = read(home)? else {
            return Ok(());
        };
        let mut frontier = std::fs::read_to_string(dir(home).join(FRONTIER))
            .ok()
            .and_then(|text| Frontier::parse(&text).ok())
            .unwrap_or_default();
        store.extend_frontier(&mut frontier)?;
        write(home, &frontier, &key)?;
        Ok(())
    })();
}

fn write(home: &Home, frontier: &Frontier, key: &SigningKey) -> Result<Written> {
    let checkpoint = Checkpoint {
        origin: key.verifier().name().to_owned(),
        size: frontier.size(),
        root: frontier.root(),
    };
    let note = key.sign(&checkpoint)?;
    let dir = dir(home);
    // Named by size, so they sort; the key's fingerprint keeps two keys'
    // checkpoints of one size apart.
    let path = dir.join(file_name(&checkpoint, key));
    crate::home::write_private(&path, note.as_bytes())?;
    crate::home::write_private(&dir.join(FRONTIER), frontier.encode().as_bytes())?;
    Ok(Written {
        path,
        note,
        checkpoint,
    })
}

fn file_name(checkpoint: &Checkpoint, key: &SigningKey) -> String {
    format!("{:012}-{}.txt", checkpoint.size, short(key.verifier()))
}

/// The first 8 hex characters of the key's name: which key signed a file.
fn short(key: &VerifierKey) -> String {
    key.name()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .chars()
        .take(8)
        .collect()
}

/// The newest checkpoint `key` signed in `home`: its file and note.
pub fn latest(home: &Home, key: &VerifierKey) -> Option<(PathBuf, String)> {
    let suffix = format!("-{}.txt", short(key));
    let newest = std::fs::read_dir(dir(home))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&suffix))
        })
        .max()?;
    let note = std::fs::read_to_string(&newest).ok()?;
    Some((newest, note))
}

#[cfg(test)]
mod tests;
