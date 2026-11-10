use super::*;

/// Each backend's pin, as the lock records it: the Claude Code block goes with
/// the hook file, Codex's config by the part OpenMoat owns, Cursor's file whole.
#[test]
fn each_backend_pins_its_settings_file_as_the_lock_always_has() {
    let pin = |host: Host| backend(host).map(SandboxBackend::pin);
    assert!(matches!(pin(Host::ClaudeCode), Some(Pin::WithHooks)));
    assert!(matches!(pin(Host::Codex), Some(Pin::Part { .. })));
    assert!(matches!(pin(Host::Cursor), Some(Pin::Whole(_))));
}

/// The digest the lock holds for a config: SHA-256 of `owned_part`, untouched
/// by the rest of a file its host also edits.
#[test]
fn a_part_digest_is_of_the_owned_part_and_ignores_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let profile = "default_permissions = \"moat\"\n[permissions.moat]\nx = 1\n";
    fs::write(&path, profile).unwrap();
    let first = part_digest(&path).unwrap();
    let doc: DocumentMut = profile.parse().unwrap();
    assert_eq!(
        first,
        crate::integrity::sha256_hex(super::super::codex::owned_part(&doc).as_bytes())
    );
    fs::write(&path, format!("model = \"other\"\n{profile}")).unwrap();
    assert_eq!(part_digest(&path).unwrap(), first);
    fs::write(
        &path,
        "default_permissions = \"other\"\n[permissions.moat]\nx = 1\n",
    )
    .unwrap();
    assert_ne!(part_digest(&path).unwrap(), first);
}

#[test]
fn claude_code_and_cursor_on_native_windows_go_without_a_sandbox() {
    assert!(unavailable_on(Host::ClaudeCode, true).is_some_and(|n| n.contains("WSL2")));
    assert_eq!(unavailable_on(Host::Codex, true), None);
    assert_eq!(unavailable_on(Host::ClaudeCode, false), None);
    assert!(unavailable_on(Host::Cursor, true).is_some());
    assert_eq!(unavailable_on(Host::Cursor, false), None);
    assert_eq!(unavailable(Host::ClaudeCode).is_some(), cfg!(windows));
}

#[test]
fn claude_code_codex_and_cursor_get_a_sandbox_in_that_order() {
    let hosts: Vec<Host> = hosts().collect();
    assert_eq!(hosts, [Host::ClaudeCode, Host::Codex, Host::Cursor]);
    assert_eq!(format(Host::OpenClaw), None);
    assert_eq!(format(Host::Continue), None);
    let files: Vec<&str> = hosts
        .iter()
        .filter_map(|h| h.spec().sandbox.as_ref().map(|s| s.file))
        .collect();
    assert_eq!(files, ["settings.json", "config.toml", "sandbox.json"]);
}
