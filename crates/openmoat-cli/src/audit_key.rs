//! The audit key's file, `~/.moat/audit.key` (ADR-100), and the audit log
//! handles that hold it.
//!
//! Every event the log records carries the key's MAC of its chain hash, so a
//! log rewritten by someone who can write the database but not read the key
//! no longer verifies. The key is kept as OpenMoat's other keys are: random,
//! written once and owner-only by `home::write_private_new`, refused when
//! others may read or replace it (`key_file::read`), and denied to agents by
//! `kernel-self` and the host sandboxes generated from it.
//!
//! The key is made when a writer finds none and the log has no keyed events
//! yet: at `openmoat init`, or at the first call after an upgrade to schema
//! version 12. A writer that finds no key while the log has keyed events, or a
//! key it cannot use, records nothing: every call it decides is then denied
//! for an audit error, as for any log that cannot take a row. Making a new key
//! there would leave the earlier keyed events unverifiable for good, and would
//! let whoever deleted the key start a log that looks intact.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{ChainKey, EventId, Store};
use zeroize::Zeroizing;

use crate::home::Home;

/// The key file in OpenMoat's state directory.
pub const KEY_FILE: &str = "audit.key";

/// Where the audit key of `home` is.
pub fn path(home: &Home) -> PathBuf {
    home.root().join(KEY_FILE)
}

/// The audit key of `home`: `None` when there is none, an error when the file
/// is there but cannot be used (others may read or replace it, or it does not
/// parse). The error names the file, never its contents.
pub fn read(home: &Home) -> Result<Option<ChainKey>> {
    let path = path(home);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let text = crate::key_file::read(&path)?;
    let key = ChainKey::parse(&text).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(key))
}

/// The key `store`'s writer records with: the one in `home`, or a new one when
/// there is none and the log has no keyed events yet.
fn for_writing(home: &Home, store: &Store) -> Result<ChainKey> {
    if let Some(key) = read(home)? {
        return Ok(key);
    }
    let path = path(home);
    if store.has_keyed_events()? {
        bail!(
            "the audit key {} is missing, but the audit log holds events keyed with it, so \
             OpenMoat records nothing more (a new key would leave those events unverifiable). \
             Put the key back from a backup, or move the audit log aside as evidence and run \
             `openmoat init` to start a new log with a new key",
            path.display()
        );
    }
    // No keyed event yet, so no writer holds a key: the newest event now is
    // the last one written before the key.
    let after = store.latest_id()?.unwrap_or(EventId(0));
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut_slice())
        .map_err(|e| anyhow::Error::msg(e.to_string()))
        .context("reading random bytes for the audit key")?;
    let made = ChainKey::new(*raw, after);
    // Two writers making it at once: the first file is kept, and both use it.
    crate::home::write_private_new(&path, made.encode().as_bytes())?;
    read(home)?.with_context(|| format!("{} is gone just after it was made", path.display()))
}

/// The audit log of `home`, created when missing, keyed for writing: what
/// `openmoat init` opens. A log without events starts with a new key when the
/// one there was made for a longer log (the person moved the old log aside)
/// or cannot be used: there is nothing for the old key to vouch for.
pub fn open(home: &Home) -> Result<Store> {
    let store = Store::open(&home.audit_path())?;
    if store.latest_id()?.is_none() {
        let stale = read(home).map_or(true, |key| key.is_some_and(|k| k.after().0 > 0));
        if stale {
            let path = path(home);
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    let key = for_writing(home, &store)?;
    Ok(store.with_chain_key(key))
}

/// The existing audit log of `home`, keyed for writing: what every writer of
/// events opens.
pub fn open_existing(home: &Home) -> Result<Store> {
    let path = home.audit_path();
    let store =
        Store::open_existing(&path).with_context(|| format!("opening {}", path.display()))?;
    let key = for_writing(home, &store)?;
    Ok(store.with_chain_key(key))
}

#[cfg(test)]
mod tests;
