//! Per-key digests of pinned JSON and TOML files, so drift can name the
//! top-level keys that changed (#288). They only describe drift; whether a file
//! drifted is still decided by its digest in [`super::Lock::entries`].

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::digest::{COSMETIC_KEY, is_claude_settings};
use super::sha256_hex;

/// Top-level key → SHA-256 of its value, for a `.json` file holding an object or
/// a `.toml` file. `None` for any other file, or one that cannot be read or parsed.
pub(super) fn key_digests(path: &Path) -> Option<BTreeMap<String, String>> {
    key_digests_of(path, &fs::read(path).ok()?)
}

/// [`key_digests`] of `contents`, already read from `path`.
pub(super) fn key_digests_of(path: &Path, contents: &[u8]) -> Option<BTreeMap<String, String>> {
    let text = std::str::from_utf8(contents).ok()?;
    match path.extension()?.to_str()? {
        "json" => {
            let value: serde_json::Value = serde_json::from_str(text).ok()?;
            object_digests(value.as_object()?, is_claude_settings(path))
        }
        "toml" => {
            let doc: toml_edit::DocumentMut = text.parse().ok()?;
            // A table's own `Display` leaves out its sub-tables; a document
            // holding only that key prints all of it.
            let digests = doc.as_table().iter().map(|(k, item)| {
                let mut one = toml_edit::DocumentMut::new();
                one.insert(k, item.clone());
                (k.to_owned(), sha256_hex(one.to_string().as_bytes()))
            });
            Some(digests.collect())
        }
        _ => None,
    }
}

/// Key → SHA-256 of its value's compact serialisation. In a Claude Code
/// settings file (`settings`) the key its digest leaves out is not named as a
/// change either.
pub(super) fn object_digests(
    object: &serde_json::Map<String, serde_json::Value>,
    settings: bool,
) -> Option<BTreeMap<String, String>> {
    let digest = |v| serde_json::to_vec(v).ok().map(|b| sha256_hex(&b));
    object
        .iter()
        .filter(|(k, _)| !(settings && *k == COSMETIC_KEY))
        .map(|(k, v)| Some((k.clone(), digest(v)?)))
        .collect()
}

/// The keys whose digests differ between `pinned` and `now`: changed, added
/// or removed.
pub(super) fn differing<'a>(
    pinned: &'a BTreeMap<String, String>,
    now: &'a BTreeMap<String, String>,
) -> impl Iterator<Item = &'a String> {
    let changed_or_removed = pinned
        .iter()
        .filter(|(k, v)| now.get(*k) != Some(*v))
        .map(|(k, _)| k);
    let added = now.keys().filter(|k| !pinned.contains_key(*k));
    changed_or_removed.chain(added)
}

/// `changed hooks; added theme`: the top-level keys that differ between the
/// pinned digests and the current ones. `None` when no top-level key differs.
/// Key names come from a file an agent may have written, so they are escaped
/// before they reach a terminal.
pub(super) fn describe(
    pinned: &BTreeMap<String, String>,
    now: &BTreeMap<String, String>,
) -> Option<String> {
    let changed = pinned
        .iter()
        .filter(|(k, v)| now.get(*k).is_some_and(|n| n != *v))
        .map(|(k, _)| k);
    let added = now.keys().filter(|k| !pinned.contains_key(*k));
    let removed = pinned.keys().filter(|k| !now.contains_key(*k));
    let groups: [(&str, Vec<&String>); 3] = [
        ("changed", changed.collect()),
        ("added", added.collect()),
        ("removed", removed.collect()),
    ];
    let parts: Vec<String> = groups
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(verb, keys)| {
            let names: Vec<String> = keys.iter().map(|k| k.escape_debug().to_string()).collect();
            format!("{verb} {}", names.join(", "))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::{Drift, Lock};
    use super::*;

    fn pinned(name: &str, contents: &str) -> (tempfile::TempDir, PathBuf, Lock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&path)).unwrap();
        (dir, path, lock)
    }

    fn message(lock: &Lock, path: &Path) -> String {
        lock.verify_one(path).unwrap().to_string()
    }

    /// `theme` is not pinned in a Claude Code settings file, so it is not named
    /// either; another JSON file still names it.
    #[test]
    fn json_drift_names_changed_added_and_removed_keys() {
        let (_dir, path, lock) = pinned("settings.json", r#"{"hooks":{"a":1},"env":{}}"#);
        fs::write(&path, r#"{"hooks":{"a":2},"theme":"light","model":"x"}"#).unwrap();
        assert!(
            message(&lock, &path)
                .ends_with("settings.json was modified: changed hooks; added model; removed env"),
            "{}",
            message(&lock, &path)
        );
    }

    #[test]
    fn toml_drift_names_changed_tables() {
        let (_dir, path, lock) =
            pinned("config.toml", "model = \"a\"\n[permissions.moat]\nx = 1\n");
        fs::write(&path, "model = \"a\"\n[permissions.moat]\nx = 2\n").unwrap();
        assert!(message(&lock, &path).ends_with("was modified: changed permissions"));
    }

    #[test]
    fn without_a_baseline_the_message_stays_plain() {
        let (_dir, path, mut lock) = pinned("settings.json", r#"{"hooks":{}}"#);
        lock.keys.clear();
        fs::write(&path, r#"{"hooks":{"a":1}}"#).unwrap();
        assert!(matches!(lock.verify_one(&path), Some(Drift::Modified(_))));

        let (_dir, path, lock) = pinned("settings.json", r#"{"hooks":{}}"#);
        fs::write(&path, r#"{"hooks":"#).unwrap();
        assert!(
            matches!(lock.verify_one(&path), Some(Drift::Modified(_))),
            "a file that no longer parses has no keys to compare"
        );
    }

    #[test]
    fn a_lock_without_keys_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("policy.lock");
        fs::write(
            &lock_path,
            r#"{"version":1,"pinned_at_ms":0,"binary":"","entries":{}}"#,
        )
        .unwrap();
        assert!(Lock::load(&lock_path).unwrap().keys.is_empty());
    }

    #[test]
    fn key_names_are_escaped() {
        let pinned = BTreeMap::new();
        let now = BTreeMap::from([("\u{1b}[2Jx".to_owned(), String::new())]);
        assert_eq!(describe(&pinned, &now).unwrap(), r"added \u{1b}[2Jx");
        // Invisible and bidirectional characters are escaped too, so a key
        // cannot show the person reading `moat doctor` something else.
        let now = BTreeMap::from([("\u{202e}SSH\u{200b}".to_owned(), String::new())]);
        assert_eq!(
            describe(&pinned, &now).unwrap(),
            r"added \u{202e}SSH\u{200b}"
        );
    }
}
