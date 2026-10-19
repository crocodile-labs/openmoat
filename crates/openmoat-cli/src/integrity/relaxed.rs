//! Drift in a Claude Code `settings.json` that leaves every guard decision as
//! it was, so the guard keeps deciding each call instead of denying them all.
//!
//! Such drift is still drift: `moat status` and `moat doctor` report it, and
//! only a person re-pins it (`moat doctor --accept`). What may drift is an
//! explicit allowlist of keys. Any other key, a file that no longer parses, a
//! symlink, a removed rule OpenMoat wrote, or a lock without the baseline to
//! compare against counts as tampering, and the guard denies every call.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use openmoat_core::Decision;
use serde_json::{Map, Value};

use super::digest::is_claude_settings;
use super::keys::{differing, object_digests};
use super::{Drift, Lock, deny_for};
use crate::home::Home;
use crate::install::Recorded;

/// Top-level keys of a Claude Code `settings.json` that may change while the
/// guard keeps deciding. Each changes only how Claude Code looks, words its
/// replies or asks the person itself. None runs a program, loads code, sets
/// the endpoint, or changes a hook, and the hook still decides every call.
/// `theme` is left out of the digest altogether (`digest.rs`); the model the
/// person picks is in [`MODEL_KEYS`].
const RELAXED_KEYS: &[&str] = &[
    // The JSON schema an editor validates the file with; Claude Code ignores it.
    "$schema",
    // Whether and how long the model thinks: same model, same endpoint.
    "alwaysThinkingEnabled",
    "effortLevel",
    // The text Claude Code adds to commits and pull requests.
    "attribution",
    "includeCoAuthoredBy",
    // Notes for Claude Code's auto mode, which decides only Claude Code's own
    // prompts; a hook deny stands in every mode.
    "autoMode",
    // How long Claude Code keeps its transcripts; OpenMoat's audit log is its own.
    "cleanupPeriodDays",
    // The language and style of replies: wording only.
    "language",
    "outputStyle",
    // Display only: motion, spinner, turn timing.
    "prefersReducedMotion",
    "showTurnDuration",
    "spinnerTipsEnabled",
    "spinnerTipsOverride",
    "spinnerVerbs",
    // Whether Claude Code's file picker lists ignored files; the hook decides
    // every read whatever the picker shows.
    "respectGitignore",
];

/// Whether a value has the shape a key allows.
type Shape = fn(&Value) -> bool;

/// Top-level keys Claude Code writes itself when the person switches models
/// (`/model`, #591), each with the only shape its value may take. The model
/// is a name: the endpoint it is sent to (`env`), the key (`apiKeyHelper`) and
/// every hook stay pinned, so it changes which model answers, never what runs
/// or what OpenMoat allows. A value of any other shape, an object or a list,
/// is drift like any other key's. A removed key has no value and may go.
const MODEL_KEYS: &[(&str, Shape)] = &[
    ("model", Value::is_string),
    ("switchModelsOnFlag", is_scalar),
];

/// The top-level key whose own keys are checked one by one.
const PERMISSIONS: &str = "permissions";
/// The list in [`PERMISSIONS`] that holds the rules OpenMoat wrote.
const DENY: &str = "deny";

/// Keys of `permissions` that may change: Claude Code's own permission lists
/// and modes. They decide only whether Claude Code asks the person about a
/// call the hook left to it; Claude Code runs the `PreToolUse` hook in every
/// mode and a hook deny is final whatever these say.
const RELAXED_PERMISSIONS: &[&str] = &[
    "allow",
    "ask",
    // Only while every rule OpenMoat wrote stays (`keeps_owned_rules`).
    DENY,
    // `default`, `acceptEdits`, `plan`, `bypassPermissions`: the hook runs in each.
    "defaultMode",
    // More working directories for Claude Code. OpenMoat's project is the git
    // root, and its policy decides every path a call names.
    "additionalDirectories",
    // Narrows what sandboxed commands and file tools may read. Turning it off
    // widens only the OS sandbox: no guard decision reads the sandbox's state,
    // and `moat status` shows the agent as `hook only` while it is off.
    "blockReadsOutsideWorkingDirectories",
];

/// The lock as `moat guard` decides by it.
#[derive(Debug, Default)]
pub struct Checked {
    /// The `kernel-integrity` deny, when anything drifted beyond the allowlist.
    pub deny: Option<Decision>,
    /// Drift the guard decides through: allowlisted keys of a Claude Code
    /// settings file only. Reported, never accepted.
    pub relaxed: Vec<Drift>,
}

/// [`super::violation`] for `moat guard` and `moat policy check`: no deny
/// while every drift is allowlisted settings drift, which is returned instead.
pub fn check(home: &Home) -> Result<Checked> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let lock = Lock::load(&lock_path)?;
    let drift = lock.verify();
    Ok(split(home, &lock, drift))
}

/// Sort `drift`, found by `lock`, into a deny or relaxed drift. Relaxed only
/// when all of it is: one tampered file denies every call, as it always did.
pub fn split(home: &Home, lock: &Lock, drift: Vec<Drift>) -> Checked {
    if drift.is_empty() {
        return Checked::default();
    }
    // `hosts.json` is pinned as well: when it drifted, that drift denies.
    let relaxed = Recorded::load(home)
        .is_ok_and(|r| drift.iter().all(|d| is_relaxed(lock, d, &r.claude_rules)));
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

/// The digests of the `permissions` keys of the Claude Code settings file at
/// `path`, pinned with it; `None` for any other file or one without them.
pub(super) fn permission_digests(path: &Path) -> Option<BTreeMap<String, String>> {
    let root = settings_object(path)?;
    object_digests(root.get(PERMISSIONS)?.as_object()?, false)
}

/// Whether `drift` touches only allowlisted keys of a Claude Code settings
/// file, `owned` being the `permissions.deny` rules OpenMoat wrote there.
fn is_relaxed(lock: &Lock, drift: &Drift, owned: &[String]) -> bool {
    // A plain `Modified` has no keys to compare: no baseline, no object, a link.
    let Drift::KeysChanged(path, _) = drift else {
        return false;
    };
    let stored = path.to_string_lossy();
    let Some(pinned) = lock.keys.get(stored.as_ref()) else {
        return false;
    };
    let Some(root) = settings_object(path) else {
        return false;
    };
    let Some(now) = object_digests(&root, true) else {
        return false;
    };
    let pinned_permissions = lock.permission_keys.get(stored.as_ref());
    let had_permissions = pinned.contains_key(PERMISSIONS);
    differing(pinned, &now).all(|key| {
        RELAXED_KEYS.contains(&key.as_str())
            || model_key_relaxed(key, &root)
            || (key == PERMISSIONS
                && permissions_relaxed(pinned_permissions, had_permissions, &root, owned))
    })
}

/// Whether `key` is one of [`MODEL_KEYS`] and its value in `root`, if any,
/// has the shape that key allows.
fn model_key_relaxed(key: &str, root: &Map<String, Value>) -> bool {
    MODEL_KEYS
        .iter()
        .any(|(name, shape)| *name == key && root.get(key).is_none_or(shape))
}

/// A string, number or boolean: a value with no structure inside it.
fn is_scalar(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_boolean()
}

/// The settings object at `path`, read once; `None` unless it is a regular
/// Claude Code settings file holding a JSON object.
fn settings_object(path: &Path) -> Option<Map<String, Value>> {
    if !is_claude_settings(path) || !fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    match serde_json::from_slice(&fs::read(path).ok()?).ok()? {
        Value::Object(root) => Some(root),
        _ => None,
    }
}

/// Whether only [`RELAXED_PERMISSIONS`] keys of `permissions` changed and the
/// rules OpenMoat wrote are all still denied.
fn permissions_relaxed(
    pinned: Option<&BTreeMap<String, String>>,
    had_permissions: bool,
    root: &Map<String, Value>,
    owned: &[String],
) -> bool {
    let empty = Map::new();
    let now = match root.get(PERMISSIONS) {
        None => &empty,
        Some(Value::Object(permissions)) => permissions,
        Some(_) => return false,
    };
    // Without the pinned keys (a lock written before them, or a pinned value
    // that was no object) nothing tells a toggle from a removed rule.
    let none = BTreeMap::new();
    let pinned = match pinned {
        Some(pinned) => pinned,
        None if !had_permissions => &none,
        None => return false,
    };
    let Some(digests) = object_digests(now, false) else {
        return false;
    };
    let mut changed = differing(pinned, &digests);
    changed.all(|key| RELAXED_PERMISSIONS.contains(&key.as_str()))
        && (pinned.get(DENY) == digests.get(DENY) || keeps_owned_rules(now, owned))
}

/// Whether `permissions.deny` still holds every rule OpenMoat wrote. With no
/// record of them a changed list cannot be told from a removed rule, so no.
fn keeps_owned_rules(permissions: &Map<String, Value>, owned: &[String]) -> bool {
    let Some(list) = permissions.get(DENY).and_then(Value::as_array) else {
        return false;
    };
    !owned.is_empty()
        && owned
            .iter()
            .all(|rule| list.iter().any(|v| v.as_str() == Some(rule.as_str())))
}

#[cfg(test)]
mod tests;
