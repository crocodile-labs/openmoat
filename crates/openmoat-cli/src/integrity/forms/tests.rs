use std::fs;
use std::path::{Path, PathBuf};

use super::super::{Lock, sha256_hex};
use super::*;

const OURS: &str = r#""plugins":{"entries":{"openmoat":{"enabled":true}}}"#;

fn with_server(command: &str) -> String {
    format!(r#"{{{OURS},"mcp":{{"servers":{{"a":{{"command":"{command}"}}}}}}}}"#)
}

fn host(id: &str) -> Host {
    id.parse().unwrap()
}

fn file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn another_hosts_file_that_looks_like_openclaws_drifts_on_its_mcp_servers() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "mcp.json", &with_server("x"));
    let pins = std::slice::from_ref(&path);
    let unowned = Lock::pin(Path::new("/x/moat"), pins).unwrap();
    // Owned by a host without a pinned form: still its bytes.
    let cursor = [(path.clone(), host("cursor"))];
    let other = Lock::pin_owned(Path::new("/x/moat"), pins, &cursor).unwrap();
    fs::write(&path, with_server("y")).unwrap();
    for lock in [unowned, other] {
        assert_eq!(lock.pinned_forms, Some(BTreeMap::new()));
        assert!(lock.verify_one(&path).is_some());
    }
}

#[test]
fn openclaws_own_file_does_not_drift_on_its_mcp_servers_alone() {
    let dir = tempfile::tempdir().unwrap();
    // Any name: `OPENCLAW_CONFIG_PATH` may name the file.
    let path = file(dir.path(), "gateway.json5", &with_server("x"));
    let owner = [(path.clone(), host("openclaw"))];
    let lock = Lock::pin_owned(Path::new("/x/moat"), std::slice::from_ref(&path), &owner).unwrap();
    // The owner survives a save and a load.
    let saved = dir.path().join("policy.lock");
    lock.save(&saved).unwrap();
    let lock = Lock::load(&saved).unwrap();
    assert_eq!(
        lock.owners(),
        [(PathBuf::from(super::super::key(&path)), host("openclaw"))]
    );
    fs::write(&path, with_server("y")).unwrap();
    assert_eq!(lock.verify_one(&path), None);
    fs::write(&path, format!("{{{OURS},\"x\":1}}")).unwrap();
    assert!(lock.verify_one(&path).is_some());
}

/// A lock as `main` wrote it before #653: no `pinned_forms`, OpenClaw's
/// file pinned in its pinned form, chosen by content.
fn legacy_lock(pins: &[(&Path, String)]) -> Lock {
    let entries: serde_json::Map<String, serde_json::Value> = pins
        .iter()
        .map(|(path, digest)| (super::super::key(path), digest.clone().into()))
        .collect();
    let text = serde_json::json!({
        "version": 1,
        "pinned_at_ms": 0,
        "binary": "/x/moat",
        "entries": entries,
    });
    Lock::parse(text.to_string().as_bytes(), Path::new("policy.lock")).unwrap()
}

/// The digest `main` pinned an OpenClaw configuration by.
fn legacy_form_digest(text: &str) -> String {
    let value = crate::json5::parse(text).unwrap().value;
    let form = form_of(host("openclaw")).unwrap();
    sha256_hex(&serde_json::to_vec(&(form.shape)(value).unwrap()).unwrap())
}

#[test]
fn a_lock_from_before_the_owner_was_recorded_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let openclaw = file(dir.path(), "openclaw.json", &with_server("x"));
    let other = file(dir.path(), "hooks.json", "{}");
    let lock = legacy_lock(&[
        (&openclaw, legacy_form_digest(&with_server("x"))),
        (&other, sha256_hex(b"{}")),
    ]);
    assert_eq!(lock.pinned_forms, None);
    assert_eq!(lock.verify(), []);
    // OpenClaw's servers are still the MCP pins' to decide; anything else drifts.
    fs::write(&openclaw, with_server("y")).unwrap();
    assert_eq!(lock.verify(), []);
    fs::write(&other, "{\"a\":1}").unwrap();
    assert!(lock.verify_one(&other).is_some());
}

#[test]
fn a_lock_from_before_the_owner_was_recorded_reads_other_names_by_their_bytes() {
    let dir = tempfile::tempdir().unwrap();
    // Pinned in OpenClaw's form by content under another name: fails closed
    // once (a re-pin records the owner), even unchanged.
    let path = file(dir.path(), "settings.json5", &with_server("x"));
    let lock = legacy_lock(&[(&path, legacy_form_digest(&with_server("x")))]);
    assert!(lock.verify_one(&path).is_some());
}

#[test]
fn an_openclaw_configuration_is_pinned_without_its_mcp_servers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("openclaw.json");
    let ours = r#""plugins":{"entries":{"openmoat":{"enabled":true}}}"#;
    fs::write(&path, format!("{{{ours}}}")).unwrap();
    let owner = (path.clone(), "openclaw".parse().unwrap());
    let lock =
        Lock::pin_owned(Path::new("/x/moat"), std::slice::from_ref(&path), &[owner]).unwrap();
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

/// `openmoat mcp wrap` and `openmoat uninstall` re-pin the files they rewrote
/// through `unpin`: OpenClaw's configuration keeps its owner, so it is pinned
/// in its form again (its servers stay the MCP pins' to decide), while the
/// undone host file is forgotten.
#[test]
fn a_rewritten_openclaw_configuration_keeps_its_pinned_form() {
    let dir = tempfile::tempdir().unwrap();
    let home = crate::home::Home::at(dir.path().join("state"));
    fs::create_dir_all(dir.path().join("state")).unwrap();
    let openclaw = file(dir.path(), "gateway.json5", &with_server("x"));
    let undone = file(dir.path(), "hooks.json", "{}");
    let owner = [(openclaw.clone(), host("openclaw"))];
    Lock::pin_owned(
        Path::new("/x/moat"),
        &[openclaw.clone(), undone.clone()],
        &owner,
    )
    .unwrap()
    .save(&home.lock_path())
    .unwrap();
    // `mcp wrap` rewrote the server's command.
    fs::write(&openclaw, with_server("openmoat mcp proxy -- x")).unwrap();
    super::super::unpin(
        &home,
        std::slice::from_ref(&undone),
        std::slice::from_ref(&openclaw),
    )
    .unwrap();
    let lock = Lock::load(&home.lock_path()).unwrap();
    let stored = super::super::key(&openclaw);
    assert_eq!(lock.owners(), [(PathBuf::from(&stored), host("openclaw"))]);
    assert_eq!(
        lock.pinned_forms
            .as_ref()
            .unwrap()
            .get(&stored)
            .map(String::as_str),
        Some("openclaw")
    );
    assert!(!lock.entries.contains_key(&super::super::key(&undone)));
    assert_eq!(lock.verify_one(&openclaw), None);
    // still its form: a server change is not drift, anything else is
    fs::write(&openclaw, with_server("y")).unwrap();
    assert_eq!(lock.verify_one(&openclaw), None);
    fs::write(&openclaw, format!("{{{OURS},\"x\":1}}")).unwrap();
    assert!(lock.verify_one(&openclaw).is_some());
}
