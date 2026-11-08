use std::fs;

use super::*;

fn spec(host: Host) -> &'static SystemSettingsSpec {
    host.spec().system_settings.as_ref().unwrap()
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap();
    path
}

fn off(host: Host, files: &[PathBuf]) -> Option<String> {
    switched_off_in(host, spec(host), files, Path::new("/h/settings.json"))
}

#[test]
fn claude_code_managed_settings_that_turn_hooks_off_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let managed = write(
        dir.path(),
        "managed-settings.json",
        r#"{"disableAllHooks": true}"#,
    );
    let why = off(Host::ClaudeCode, std::slice::from_ref(&managed)).unwrap();
    assert!(
        why.contains("disableAllHooks") && why.contains("managed-settings.json"),
        "{why}"
    );

    fs::write(&managed, r#"{"allowManagedHooksOnly": true}"#).unwrap();
    let why = off(Host::ClaudeCode, std::slice::from_ref(&managed)).unwrap();
    assert!(why.contains("allowManagedHooksOnly"), "{why}");

    // With OpenMoat's hook among the managed ones, it still runs.
    fs::write(
        &managed,
        r#"{"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [{"hooks": [
            {"type": "command", "command": "/usr/local/bin/openmoat guard --host claude-code"}]}]}}"#,
    )
    .unwrap();
    assert_eq!(off(Host::ClaudeCode, &[managed]), None);
}

#[test]
fn a_claude_code_drop_in_is_read_after_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let managed = write(dir.path(), "managed-settings.json", "{}");
    write(
        dir.path(),
        "managed-settings.d/10-team.json",
        r#"{"disableAllHooks": true}"#,
    );
    write(
        dir.path(),
        "managed-settings.d/notes.txt",
        r#"{"disableAllHooks": true}"#,
    );
    let listed = with_drop_ins(managed, spec(Host::ClaudeCode).drop_ins);
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert!(listed[1].ends_with("10-team.json"));
    let why = off(Host::ClaudeCode, &listed).unwrap();
    assert!(why.contains("10-team.json"), "{why}");
}

#[test]
fn gemini_cli_system_settings_and_codex_requirements_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let gemini = write(
        dir.path(),
        "settings.json",
        r#"{"hooksConfig": {"enabled": false}}"#,
    );
    let why = off(Host::GeminiCli, &[gemini]).unwrap();
    assert!(why.contains("hooksConfig.enabled"), "{why}");

    let codex = write(
        dir.path(),
        "requirements.toml",
        "[features]\nhooks = false\n",
    );
    let why = off(Host::Codex, std::slice::from_ref(&codex)).unwrap();
    assert!(why.contains("features.hooks"), "{why}");
    fs::write(&codex, "allow_managed_hooks_only = true\n").unwrap();
    let why = off(Host::Codex, std::slice::from_ref(&codex)).unwrap();
    assert!(why.contains("allow_managed_hooks_only"), "{why}");
    fs::write(
        &codex,
        "allow_managed_hooks_only = true\n[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\n\
         type = \"command\"\ncommand = \"/opt/bin/openmoat guard --host codex\"\n",
    )
    .unwrap();
    assert_eq!(off(Host::Codex, &[codex]), None);
}

/// Missing, unreadable and broken files say nothing and never fail.
#[test]
fn missing_unreadable_or_broken_files_say_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("managed-settings.json");
    assert_eq!(off(Host::ClaudeCode, std::slice::from_ref(&missing)), None);
    let broken = write(dir.path(), "broken.json", "{ not json");
    assert_eq!(off(Host::ClaudeCode, &[broken]), None);
    let directory = dir.path().join("a-directory.json");
    fs::create_dir(&directory).unwrap();
    assert_eq!(off(Host::ClaudeCode, &[directory]), None);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let locked = write(dir.path(), "locked.json", r#"{"disableAllHooks": true}"#);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads it anyway; anyone else is refused and hears nothing.
        if fs::read(&locked).is_err() {
            assert_eq!(off(Host::ClaudeCode, &[locked]), None);
        }
    }
}

#[test]
fn only_the_platforms_files_are_read_and_a_variable_moves_one() {
    let spec = spec(Host::GeminiCli);
    let linux = files(spec, Platform::Linux, &|_| None);
    assert_eq!(
        linux,
        [
            PathBuf::from("/etc/gemini-cli/settings.json"),
            PathBuf::from("/etc/gemini-cli/system-defaults.json")
        ]
    );
    let moved = files(spec, Platform::MacOs, &|name| {
        (name == "GEMINI_CLI_SYSTEM_SETTINGS_PATH").then(|| "/x/s.json".into())
    });
    assert_eq!(moved[0], PathBuf::from("/x/s.json"));
    assert!(moved[1].starts_with("/Library/Application Support/GeminiCli"));
    assert!(files(spec, Platform::Windows, &|_| None)[0].starts_with("C:/ProgramData"));
}

#[test]
fn hosts_without_system_settings_have_none() {
    assert!(Host::Cursor.spec().system_settings.is_none());
    assert_eq!(switched_off(Host::Cursor, Path::new("/h")), None);
}
