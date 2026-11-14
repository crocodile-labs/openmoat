//! Drift in a host's hook file limited to the keys its spec lists as relaxed
//! ([`openmoat_hosts::InstallSpec::relaxed_keys`]), compared by the rest of
//! the file ([`RelaxedCheck::Rest`]): Gemini CLI's `settings.json`, which
//! Gemini CLI rewrites itself for a new model, theme or sign-in method.
//!
//! The lock pins such a file twice: whole, as every hook file, and by the
//! digest of what is left with the relaxed keys taken out ([`pinned_rest`]).
//! A drifted file whose rest still has that digest changed only relaxed keys,
//! each to a value of its shape, and the guard decides through it. Anything
//! else in the file, a value of another shape, a file that no longer parses or
//! a lock without the rest's digest denies, as all drift does.

use std::fs;
use std::path::Path;

use openmoat_hosts::{InstallSpec, RelaxedCheck, RelaxedKey};
use serde_json::{Map, Value};

use super::sha256_hex;

/// `install`, when its relaxed keys are compared by the rest of the file.
fn by_rest(install: &InstallSpec) -> Option<&InstallSpec> {
    (!install.relaxed_keys.is_empty() && install.relaxed_check == RelaxedCheck::Rest)
        .then_some(install)
}

/// The digest to pin for the regular file at `path`, the hook file of the
/// host `install` is of, without its relaxed keys; `None` for a host whose
/// keys are compared otherwise, a link, or a file that holds no JSON object.
pub(super) fn pinned_rest(path: &Path, install: &InstallSpec) -> Option<String> {
    let install = by_rest(install)?;
    if !fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    rest_digest(&fs::read(path).ok()?, install)
}

/// Whether `bytes`, the drifted hook file of the host `install` is of as the
/// lock check read them, differ from the pinned file only in relaxed keys:
/// their rest has the `pinned` digest.
pub(super) fn only_relaxed(bytes: &[u8], install: &InstallSpec, pinned: &str) -> bool {
    by_rest(install)
        .and_then(|install| rest_digest(bytes, install))
        .is_some_and(|rest| rest == pinned)
}

/// The SHA-256 of the JSON object in `bytes` with each relaxed key that holds
/// a value of its shape taken out, serialised compactly with sorted keys. A
/// value of another shape stays, so changing it is drift. Without the keys
/// the file's pin leaves out too ([`InstallSpec::unpinned_keys`]).
fn rest_digest(bytes: &[u8], install: &InstallSpec) -> Option<String> {
    let Value::Object(mut root) = serde_json::from_slice(bytes).ok()? else {
        return None;
    };
    for key in install.unpinned_keys {
        root.remove(*key);
    }
    for key in install.relaxed_keys {
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
        if object.get(*first).is_some_and(|v| key.shape.holds(v, &[])) {
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
