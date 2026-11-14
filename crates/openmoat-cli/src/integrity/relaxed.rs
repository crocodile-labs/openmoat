//! Drift in a host's hook file limited to the keys its spec lists as relaxed
//! ([`openmoat_hosts::InstallSpec::relaxed_keys`]) that leaves every guard
//! decision as it was, so the guard keeps deciding each call instead of
//! denying them all. A host's keys are compared by the rest of the file
//! (`spec_keys.rs`) or key by key (here, Claude Code's `settings.json`), as its
//! spec's [`openmoat_hosts::InstallSpec::relaxed_check`] says.
//!
//! Such drift is still drift: `moat status` and `moat doctor` report it, and
//! only a person re-pins it (`moat doctor --accept`). What may drift is an
//! explicit allowlist of keys, applied only to a file the lock pinned as that
//! host's hook file (`owner.rs`). Any other key, a file that no longer parses,
//! a symlink, a removed rule OpenMoat wrote, or a lock without the baseline to
//! compare against counts as tampering, and the guard denies every call.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{InstallSpec, RelaxedCheck, RelaxedKey};
use serde_json::{Map, Value};

use super::keys::{differing, object_digests};
use super::spec_keys;
use super::{Drift, Kept, Lock, deny_for};
use crate::home::Home;
use crate::install::Recorded;

/// The lock as `moat guard` decides by it.
#[derive(Debug, Default)]
pub struct Checked {
    /// The `kernel-integrity` deny, when anything drifted beyond the allowlist.
    pub deny: Option<Decision>,
    /// Drift the guard decides through: a host's relaxed keys in its hook
    /// file only. Reported, never accepted.
    pub relaxed: Vec<Drift>,
}

/// What [`check`] read, so the caller decides by the same bytes it checked.
#[derive(Debug)]
pub struct Verified {
    /// The lock, read and parsed once.
    pub lock: Lock,
    /// The state directory, reading each pinned state file that matched its
    /// pin from the bytes that matched (`kept.rs`), not from disk again.
    pub home: Home,
    /// The deny, or the settings drift decided through.
    pub checked: Checked,
}

/// [`super::violation`] for `moat guard` and `moat policy check`: no deny
/// while every drift is allowlisted settings drift, which is returned instead.
pub fn check(home: &Home) -> Result<Verified> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!(
            "no policy lock at {}; run `openmoat init`",
            lock_path.display()
        );
    }
    let lock = Lock::load(&lock_path)?;
    let (drift, home) = super::verify_state(home, &lock);
    let mut checked = split(&home, &lock, drift);
    // The guard's own file, against the digest the lock recorded (ADR-071).
    if checked.deny.is_none()
        && let Some(reason) = super::binary::check(&home, &lock).deny_reason()
    {
        checked.deny = Some(Decision::single(
            Verdict::Deny,
            super::INTEGRITY_RULE,
            reason,
        ));
    }
    Ok(Verified {
        lock,
        home,
        checked,
    })
}

/// Sort `drift`, found by `lock`, into a deny or relaxed drift. Relaxed only
/// when all of it is: one tampered file denies every call, as it always did.
/// A settings file's drift is sorted by the bytes the check read, which
/// `home` keeps ([`super::verify_state`]); without them it denies.
pub fn split(home: &Home, lock: &Lock, drift: Vec<Drift>) -> Checked {
    if drift.is_empty() {
        return Checked::default();
    }
    // `hosts.json` is pinned as well: when it drifted, that drift denies.
    let kept = home.kept();
    let relaxed =
        Recorded::load(home).is_ok_and(|r| drift.iter().all(|d| is_relaxed(lock, d, &r, kept)));
    if relaxed {
        Checked {
            deny: None,
            relaxed: drift,
        }
    } else {
        Checked {
            deny: deny_for(&drift),
            relaxed: Vec::new(),
        }
    }
}

/// The digests of the keys of the object the dotted relaxed keys of
/// `install` are in (Claude Code's `permissions`), in its hook file at
/// `path`, pinned with it; `None` for a host whose keys are compared
/// otherwise, a link, or a file without that object.
pub(super) fn parent_digests(
    path: &Path,
    install: &InstallSpec,
) -> Option<BTreeMap<String, String>> {
    if install.relaxed_check != RelaxedCheck::ByKey
        || !fs::symlink_metadata(path).ok()?.file_type().is_file()
    {
        return None;
    }
    let root = object(&fs::read(path).ok()?)?;
    let parent = RelaxedCheck::parent(install.relaxed_keys)?;
    object_digests(root.get(parent)?.as_object()?, &[])
}

/// Whether `drift` touches only the relaxed keys of the host whose hook file
/// the lock pinned there, `recorded` naming the rules OpenMoat wrote into
/// that host's file and `kept` holding the file's bytes as the check read them.
fn is_relaxed(lock: &Lock, drift: &Drift, recorded: &Recorded, kept: &Kept) -> bool {
    // A plain `Modified` has no keys to compare: no baseline, no object, a link.
    let Drift::KeysChanged(path, _) = drift else {
        return false;
    };
    let stored = path.to_string_lossy();
    let (Some(host), Some(bytes)) = (lock.hook_owner(&stored), kept.drifted(path)) else {
        return false;
    };
    let Some(install) = lock.relaxing(&stored) else {
        return false;
    };
    let owned = recorded.written_rules(host);
    match install.relaxed_check {
        RelaxedCheck::Rest => lock
            .relaxed_rest
            .get(stored.as_ref())
            .is_some_and(|pinned| spec_keys::only_relaxed(bytes, install, pinned)),
        RelaxedCheck::ByKey => by_key(lock, &stored, bytes, install, owned),
        _ => false,
    }
}

/// [`RelaxedCheck::ByKey`]: whether every top-level key whose digest changed
/// is a relaxed key holding a value of its shape (or removed), or the object
/// the dotted ones are in with only those changed in it.
fn by_key(
    lock: &Lock,
    stored: &str,
    bytes: &[u8],
    install: &InstallSpec,
    owned: &[String],
) -> bool {
    let Some(pinned) = lock.keys.get(stored) else {
        return false;
    };
    let Some(root) = object(bytes) else {
        return false;
    };
    let Some(now) = object_digests(&root, install.unpinned_keys) else {
        return false;
    };
    let keys = install.relaxed_keys;
    let parent = RelaxedCheck::parent(keys);
    differing(pinned, &now).all(|key| {
        if parent == Some(key.as_str()) {
            let pinned_inner = lock.permission_keys.get(stored);
            inner_relaxed(
                pinned_inner,
                pinned.contains_key(key),
                key,
                &root,
                keys,
                owned,
            )
        } else {
            relaxed_value(keys, None, key, root.get(key), owned)
        }
    })
}

/// Whether the key `name`, at the top (`parent` `None`) or in the object
/// `parent`, is one of `keys` and `value`, if any, has its shape. Matched by
/// the path's names, so a top-level key that is literally named
/// `permissions.allow` is no relaxed key: only `allow` inside `permissions`
/// is.
fn relaxed_value(
    keys: &[RelaxedKey],
    parent: Option<&str>,
    name: &str,
    value: Option<&Value>,
    owned: &[String],
) -> bool {
    keys.iter().any(|k| {
        let at = match k.path.split_once('.') {
            Some((outer, inner)) => parent == Some(outer) && inner == name,
            None => parent.is_none() && k.path == name,
        };
        at && match value {
            Some(value) => k.shape.holds(value, owned),
            None => k.shape.may_be_removed(),
        }
    })
}

/// The JSON object in `bytes`; `None` unless they hold one.
fn object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(bytes).ok()? {
        Value::Object(root) => Some(root),
        _ => None,
    }
}

/// Whether only relaxed keys of the object `parent` in `root` changed, each
/// to a value of its shape, against the `pinned` digests of its keys.
fn inner_relaxed(
    pinned: Option<&BTreeMap<String, String>>,
    had_parent: bool,
    parent: &str,
    root: &Map<String, Value>,
    keys: &[RelaxedKey],
    owned: &[String],
) -> bool {
    let empty = Map::new();
    let now = match root.get(parent) {
        None => &empty,
        Some(Value::Object(inner)) => inner,
        Some(_) => return false,
    };
    // Without the pinned keys (a lock written before them, or a pinned value
    // that was no object) nothing tells a toggle from a removed rule.
    let none = BTreeMap::new();
    let pinned = match pinned {
        Some(pinned) => pinned,
        None if !had_parent => &none,
        None => return false,
    };
    let Some(digests) = object_digests(now, &[]) else {
        return false;
    };
    differing(pinned, &digests)
        .all(|key| relaxed_value(keys, Some(parent), key, now.get(key), owned))
}

#[cfg(test)]
mod tests;
