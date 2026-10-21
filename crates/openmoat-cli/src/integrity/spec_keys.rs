//! Drift in a host's hook file limited to the keys its spec lists as relaxed
//! ([`openmoat_hosts::InstallSpec::relaxed_keys`]): Gemini CLI's
//! `settings.json`, which Gemini CLI rewrites itself for a new model, theme or
//! sign-in method.
//!
//! The lock pins such a file twice: whole, as every hook file, and by the
//! digest of what is left with the relaxed keys taken out ([`pinned_rest`]).
//! A drifted file whose rest still has that digest changed only relaxed keys,
//! each to a value of its shape, and the guard decides through it. Anything
//! else in the file, a value of another shape, a file that no longer parses or
//! a lock without the rest's digest denies, as all drift does.

use std::fs;
use std::path::Path;

use openmoat_hosts::{Host, RelaxedKey};
use serde_json::{Map, Value};

use super::digest::{COSMETIC_KEY, is_claude_settings};
use super::sha256_hex;

/// The relaxed keys of the host whose hook file is at `path`, found by its
/// `<dir_name>/<config_file>` ending; `None` for any other file.
pub(super) fn listed(path: &Path) -> Option<&'static [RelaxedKey]> {
    Host::ALL
        .into_iter()
        .filter_map(|host| host.spec().install.as_ref())
        .filter(|install| !install.relaxed_keys.is_empty())
        .find(|install| path.ends_with(Path::new(install.dir_name).join(install.config_file)))
        .map(|install| install.relaxed_keys)
}

/// The digest to pin for the regular file at `path` without its relaxed keys;
/// `None` for a file with none, a link, or one that holds no JSON object.
pub(super) fn pinned_rest(path: &Path) -> Option<String> {
    let keys = listed(path)?;
    if !fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    rest_digest(path, &fs::read(path).ok()?, keys)
}

/// Whether `bytes`, the drifted file at `path` as the lock check read them,
/// differ from the pinned file only in relaxed keys: their rest has the
/// `pinned` digest.
pub(super) fn only_relaxed(path: &Path, bytes: &[u8], keys: &[RelaxedKey], pinned: &str) -> bool {
    rest_digest(path, bytes, keys).is_some_and(|rest| rest == pinned)
}

/// The SHA-256 of the JSON object in `bytes` with each of `keys` that holds a
/// value of its shape taken out, serialised compactly with sorted keys. A
/// value of another shape stays, so changing it is drift. Without the
/// cosmetic key too for a settings file, whose pin leaves it out (`digest.rs`).
fn rest_digest(path: &Path, bytes: &[u8], keys: &[RelaxedKey]) -> Option<String> {
    let Value::Object(mut root) = serde_json::from_slice(bytes).ok()? else {
        return None;
    };
    if is_claude_settings(path) {
        root.remove(COSMETIC_KEY);
    }
    for key in keys {
        let names: Vec<&str> = key.path.split('.').collect();
        take_out(&mut root, &names, key);
    }
    serde_json::to_vec(&Value::Object(root))
        .ok()
        .map(|b| sha256_hex(&b))
}

/// Take the value at `names` out of `object` when it has `key`'s shape, then
/// each object on the way that is left empty, as an absent one reads the same.
/// A name on the way that holds no object leaves everything in place.
fn take_out(object: &mut Map<String, Value>, names: &[&str], key: &RelaxedKey) {
    let Some((first, rest)) = names.split_first() else {
        return;
    };
    if rest.is_empty() {
        if object.get(*first).is_some_and(|v| key.shape.holds(v)) {
            object.remove(*first);
        }
        return;
    }
    let Some(Value::Object(inner)) = object.get_mut(*first) else {
        return;
    };
    take_out(inner, rest, key);
    if inner.is_empty() {
        object.remove(*first);
    }
}

#[cfg(test)]
mod tests;
