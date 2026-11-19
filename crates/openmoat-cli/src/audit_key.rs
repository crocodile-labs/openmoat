//! The audit key's file, `~/.moat/audit.key` (ADR-101), and the audit log
//! handles that hold it.
//!
//! Every event the log records carries the key's MAC of its chain hash, so a
//! log rewritten by someone who can write the database but not read the key
//! no longer verifies. The key is kept as OpenMoat's other keys are: random,
//! written once and owner-only by `home::write_private_new` (through a
//! temporary `audit.key.<pid>.<nanos>.tmp`), refused when others may read or
//! replace it (`key_file::read`), and denied to agents by `kernel-self`
//! (`audit.key*`, so the temporary file and kept old keys too) and the host
//! sandboxes generated from it.
//!
//! When a key is made:
//!
//! - by a person's `openmoat init`, for a log with no keyed events yet;
//! - by any writer, for an empty log, or in the call whose own open upgraded the
//!   log to schema version 12 (adding the MAC column): the first call after
//!   an upgrade.
//!
//! Any other writer that finds no key records nothing, after a short wait for
//! a concurrent upgrade to make it: every call it decides is then denied for an
//! audit error, as for any log that cannot take a row. Making a key there would
//! let whoever can write the database strip the MACs, move version 12's mark,
//! delete the key and have a new one made over a rewritten log.
//!
//! `openmoat init` on a new log, or an empty one whose key was made for a
//! longer log or cannot be used, starts a new key, and keeps the one it
//! replaces as `audit.key.<ms>.old`: a key made for a log the person moved
//! aside as evidence still checks that log.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{ChainKey, Store};
use zeroize::Zeroizing;

use crate::home::Home;

/// The key file in OpenMoat's state directory.
pub const KEY_FILE: &str = "audit.key";

/// How long a writer that finds no key waits for one a concurrent upgrade is
/// making, before it refuses.
const UPGRADE_WAIT: Duration = Duration::from_millis(500);

/// Where the audit key of `home` is.
pub fn path(home: &Home) -> PathBuf {
    home.root().join(KEY_FILE)
}

/// The audit key of `home`: `None` when there is none, an error when the file
/// is there but cannot be used (others may read or replace it, or it does not
/// parse). The error names the file, never its contents.
pub fn read(home: &Home) -> Result<Option<ChainKey>> {
    read_at(&path(home))
}

fn read_at(path: &Path) -> Result<Option<ChainKey>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let text = crate::key_file::read(path)?;
    let key = ChainKey::parse(&text).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(key))
}

/// Who opens the log for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writer {
    /// A person's `openmoat init`.
    Person,
    /// Any other writer: the guard, the proxy, the listener.
    Process,
}

/// The key `store`'s writer records with: the one in `home`, or a new one
/// where the module documentation says one is made.
fn for_writing(home: &Home, store: &Store, writer: Writer) -> Result<ChainKey> {
    if let Some(key) = read(home)? {
        return Ok(key);
    }
    let path = path(home);
    let empty = store.latest_id()?.is_none();
    let may_make = empty
        || store.upgraded_to_keyed()
        || (writer == Writer::Person && !store.has_keyed_events()?);
    if !may_make {
        if writer == Writer::Process
            && let Some(key) = wait_for_key(home)?
        {
            return Ok(key);
        }
        if !store.has_keyed_events()? {
            bail!(
                "the audit key {} is missing and this audit log already holds events, so \
                 OpenMoat records nothing more: only an upgrade or a person's `openmoat init` makes \
                 a key for a log with events. No event in it is keyed yet, so run `openmoat init` \
                 in your terminal: it makes the key and keeps the log",
                path.display()
            );
        }
        bail!(
            "the audit key {} is missing and this audit log already holds events, so \
             OpenMoat records nothing more: only an upgrade or a person's `openmoat init` makes \
             a key for a log with events. Put the key back from a backup, or move the audit log \
             aside as evidence and run `openmoat init` to start a new log with a new key",
            path.display()
        );
    }
    let (after, after_hash) = store.key_start()?;
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut_slice())
        .map_err(|e| anyhow::Error::msg(e.to_string()))
        .context("reading random bytes for the audit key")?;
    let made = ChainKey::new(&raw, after, after_hash.as_deref());
    // Two writers making it at once: the first file is kept, and both use it.
    crate::home::write_private_new(&path, made.encode().as_bytes())?;
    read(home)?.with_context(|| format!("{} is gone just after it was made", path.display()))
}

/// The key a concurrent upgrade is making, if it appears within
/// [`UPGRADE_WAIT`].
fn wait_for_key(home: &Home) -> Result<Option<ChainKey>> {
    let deadline = Instant::now() + UPGRADE_WAIT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        if let Some(key) = read(home)? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Create the audit log of `home` when missing, and its key: what a person's
/// `openmoat init` does. A new log starts with a new key, as the module
/// documentation says; the one there before is kept beside it, not removed,
/// and where is returned.
pub fn open(home: &Home) -> Result<Option<PathBuf>> {
    let new = !home.audit_path().exists();
    let store = Store::open(&home.audit_path())?;
    let mut kept = None;
    let old = path(home);
    // An empty log that was there already keeps a key made for it (`init`
    // run again before any call); one made for a longer log, or one that
    // cannot be used, is replaced.
    let replace = new
        || (store.latest_id()?.is_none()
            && read(home).map_or(true, |key| key.is_some_and(|k| k.after().0 > 0)));
    if replace && std::fs::symlink_metadata(&old).is_ok() {
        let to = home
            .root()
            .join(format!("{KEY_FILE}.{}.old", crate::time::now_ms()));
        crate::home::keep_private(&old, &to)?;
        kept = Some(to);
    }
    for_writing(home, &store, Writer::Person)?;
    Ok(kept)
}

/// The existing audit log of `home`, keyed for writing: what every writer of
/// events opens.
pub fn open_existing(home: &Home) -> Result<Store> {
    let path = home.audit_path();
    let store =
        Store::open_existing(&path).with_context(|| format!("opening {}", path.display()))?;
    let key = for_writing(home, &store, Writer::Process)?;
    Ok(store.with_chain_key(key))
}

/// Whether the log of `home` keys its events and holds some while there is no
/// audit key: what `openmoat doctor` warns of even where version 12's mark
/// says nothing is keyed, since a database writer can move the mark.
pub fn missing_over_events(home: &Home) -> bool {
    !path(home).exists()
        && home
            .open_audit()
            .and_then(|store| Ok(store.keys_events() && store.latest_id()?.is_some()))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests;
