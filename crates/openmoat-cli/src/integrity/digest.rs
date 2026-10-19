//! The digests the lock pins a file by.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};

/// The top-level key of a Claude Code settings file left out of its digest.
/// Claude Code writes it on first run and whenever the person picks a theme, and
/// it changes only colours (#287).
pub(super) const COSMETIC_KEY: &str = "theme";

/// Whether `path` is a Claude Code settings file, pinned without [`COSMETIC_KEY`].
pub(super) fn is_claude_settings(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "settings.json")
}

/// The digest to pin for the file at `path`: the first of [`digests`].
pub(super) fn digest(path: &Path, settings: bool) -> Result<String> {
    Ok(digests(path, settings)?.swap_remove(0))
}

/// Every digest the file at `path` verifies against, the one to pin first.
///
/// With `settings` (a Claude Code settings file) whose contents parse as a JSON
/// object, the first is the digest of its canonical serialisation without
/// [`COSMETIC_KEY`]. The last is always the whole-file digest, which locks
/// written before #287 hold for settings files; it matches only identical bytes,
/// so accepting it hides nothing. A settings file that no longer parses has only
/// the whole-file digest and so no longer matches a canonical pin.
///
/// A symlink hashes its target path together with the contents, so swapping a
/// regular file for a link (or re-pointing a link) changes every digest even
/// when the bytes read through it are identical.
pub(super) fn digests(path: &Path, settings: bool) -> Result<Vec<String>> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mut link = Vec::new();
    if meta.file_type().is_symlink() {
        let target =
            fs::read_link(path).with_context(|| format!("reading link {}", path.display()))?;
        link.extend_from_slice(b"symlink:");
        link.extend_from_slice(target.to_string_lossy().as_bytes());
        link.push(b'\n');
    }
    let contents = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    if settings && let Some(canonical) = without_cosmetic_key(&contents) {
        out.push(sha256_hex(&[link.as_slice(), &canonical].concat()));
    }
    if !settings && let Some(canonical) = openclaw_without_servers(&contents) {
        out.push(sha256_hex(&[link.as_slice(), &canonical].concat()));
    }
    out.push(sha256_hex(&[link, contents].concat()));
    Ok(out)
}

/// An OpenClaw configuration that loads OpenMoat's plugin
/// (`plugins.entries.openmoat`), read as JSON5, without `mcp.servers` and
/// serialised compactly with sorted keys. The MCP pins (ADR-026) hold each
/// server's definition, so a changed server holds back only its own tools;
/// every other change, and one that removes OpenMoat's entry, is drift.
/// Comments and formatting are not part of it: they change nothing OpenClaw
/// reads.
fn openclaw_without_servers(contents: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(contents).ok()?;
    let mut value = crate::json5::parse(text).ok()?.value;
    let plugin = format!("/plugins/entries/{}", crate::install::openclaw::PLUGIN_ID);
    value.pointer(&plugin)?;
    let top = value.as_object_mut()?;
    if let Some(mcp) = top
        .get_mut("mcp")
        .and_then(serde_json::Value::as_object_mut)
    {
        mcp.remove("servers");
        // The first server added brings `mcp` with it.
        if mcp.is_empty() {
            top.remove("mcp");
        }
    }
    serde_json::to_vec(&value).ok()
}

/// The JSON object in `contents` without [`COSMETIC_KEY`], serialised compactly
/// with sorted keys (`serde_json` maps are ordered without `preserve_order`).
fn without_cosmetic_key(contents: &[u8]) -> Option<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(contents).ok()?;
    value.as_object_mut()?.remove(COSMETIC_KEY);
    serde_json::to_vec(&value).ok()
}

/// Lowercase hex SHA-256, as pinned in the lock and shown by `status`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::{Drift, Lock};
    use super::*;

    fn pinned(contents: &str) -> (tempfile::TempDir, PathBuf, Lock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, contents).unwrap();
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&path)).unwrap();
        (dir, path, lock)
    }

    #[test]
    fn theme_added_or_changed_is_not_drift() {
        let (_dir, path, lock) = pinned(r#"{"hooks":{"PreToolUse":[]}}"#);
        fs::write(&path, r#"{"hooks":{"PreToolUse":[]},"theme":"light"}"#).unwrap();
        assert_eq!(lock.verify_one(&path), None);
        fs::write(
            &path,
            "{\n  \"theme\": \"dark\",\n  \"hooks\": {\"PreToolUse\": []}\n}",
        )
        .unwrap();
        assert_eq!(lock.verify_one(&path), None);
    }

    #[test]
    fn any_other_key_changed_is_drift() {
        let (_dir, path, lock) = pinned(r#"{"hooks":{"PreToolUse":[]},"theme":"light"}"#);
        fs::write(&path, r#"{"hooks":{},"theme":"light"}"#).unwrap();
        assert!(matches!(
            lock.verify_one(&path),
            Some(Drift::Modified(_) | Drift::KeysChanged(..))
        ));
        fs::write(&path, r#"{"hooks":{"PreToolUse":[]},"model":"x"}"#).unwrap();
        assert!(matches!(
            lock.verify_one(&path),
            Some(Drift::Modified(_) | Drift::KeysChanged(..))
        ));
    }

    #[test]
    fn invalid_json_is_drift() {
        let (_dir, path, lock) = pinned(r#"{"hooks":{}}"#);
        fs::write(&path, r#"{"hooks":{}"#).unwrap();
        assert!(matches!(
            lock.verify_one(&path),
            Some(Drift::Modified(_) | Drift::KeysChanged(..))
        ));
    }

    #[test]
    fn a_whole_file_pin_from_an_older_lock_still_verifies() {
        let (_dir, path, mut lock) = pinned("{ \"hooks\": {} }\n");
        let whole = digests(&path, false).unwrap().swap_remove(0);
        lock.entries.values_mut().for_each(|d| d.clone_from(&whole));
        assert_eq!(lock.verify_one(&path), None);
        fs::write(&path, "{ \"hooks\": {}, \"theme\": \"light\" }\n").unwrap();
        assert!(
            lock.verify_one(&path).is_some(),
            "an old pin is whole-file until re-pinned"
        );
    }

    #[test]
    fn an_openclaw_configuration_is_pinned_without_its_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openclaw.json");
        let ours = r#""plugins":{"entries":{"openmoat":{"enabled":true}}}"#;
        fs::write(&path, format!("{{{ours}}}")).unwrap();
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&path)).unwrap();
        // A server added, then changed, and comments: not drift (the MCP pins
        // decide servers).
        for text in [
            format!(r#"{{{ours},"mcp":{{"servers":{{"a":{{"command":"x"}}}}}}}}"#),
            format!(
                r#"// note{}{{{ours},"mcp":{{"servers":{{"a":{{"command":"y"}}}}}}}}"#,
                "\n"
            ),
        ] {
            fs::write(&path, text).unwrap();
            assert_eq!(lock.verify_one(&path), None);
        }
        // Anything else is.
        let other_mcp = format!(r#"{{{ours},"mcp":{{"servers":{{}},"x":1}}}}"#);
        let plugins_off = r#"{"plugins":{"entries":{"openmoat":{"enabled":false}}}}"#.to_owned();
        let entry_gone = r#"{"mcp":{"servers":{}}}"#.to_owned();
        for text in [other_mcp, plugins_off, entry_gone, "{".to_owned()] {
            fs::write(&path, &text).unwrap();
            assert!(lock.verify_one(&path).is_some(), "{text}");
        }
    }

    #[test]
    fn only_settings_files_leave_out_theme() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = dir.path().join("hooks.json");
        fs::write(&hooks, "{}").unwrap();
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&hooks)).unwrap();
        fs::write(&hooks, r#"{"theme":"light"}"#).unwrap();
        assert!(matches!(
            lock.verify_one(&hooks),
            Some(Drift::Modified(_) | Drift::KeysChanged(..))
        ));
    }
}
