use super::*;
use openmoat_hosts::Host;

/// [`super::install`] with the state directory next to the hook file.
fn install(config: &HostConfig, binary: &Path, dry_run: bool) -> Result<Outcome> {
    super::install(&state_home(config), config, binary, dry_run)
}

fn state_home(config: &HostConfig) -> Home {
    Home::at(config.dir().join(".moat"))
}

const SPECS: &[HookSpec] = &[
    HookSpec {
        event: "PreToolUse",
        matcher: "Bash|Edit",
        timeout: 600,
        block_on_failure: true,
    },
    HookSpec {
        event: "ConfigChange",
        matcher: "user_settings",
        timeout: 60,
        block_on_failure: false,
    },
];

/// Claude Code older than v2.1.295, or none on `PATH`: no `onFailure`.
fn config(dir: &Path) -> HostConfig {
    HostConfig {
        host: Host::ClaudeCode,
        settings_path: dir.join("settings.json"),
        dir: dir.to_path_buf(),
        hooks: SPECS,
        format: HookFormat::Nested,
        blocks_on_failure: || false,
    }
}

/// Claude Code v2.1.295 or later.
fn config_blocking(dir: &Path) -> HostConfig {
    HostConfig {
        blocks_on_failure: || true,
        ..config(dir)
    }
}

/// The `onFailure` of our handler for `event`, if any.
fn on_failure(cfg: &HostConfig, event: &str) -> Value {
    root(cfg)["hooks"][event][0]["hooks"][0]["onFailure"].clone()
}

#[test]
fn a_current_claude_code_gets_on_failure_block_on_pre_tool_use_only() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_blocking(dir.path());
    let binary = Path::new("/x/moat");
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
    assert_eq!(on_failure(&cfg, "PreToolUse"), "block");
    assert_eq!(on_failure(&cfg, "ConfigChange"), Value::Null);
    assert_eq!(state(&cfg, binary), HookState::Installed);
    assert!(!lacks_on_failure(&cfg));
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
}

#[test]
fn an_older_claude_code_gets_no_on_failure_and_is_not_stale() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let binary = Path::new("/x/moat");
    install(&cfg, binary, false).unwrap();
    assert_eq!(on_failure(&cfg, "PreToolUse"), Value::Null);
    assert_eq!(state(&cfg, binary), HookState::Installed);
    assert!(
        lacks_on_failure(&cfg),
        "doctor says the host runs failed calls"
    );
}

#[test]
fn an_entry_without_on_failure_is_stale_once_claude_code_knows_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let binary = Path::new("/x/moat");
    install(&config(dir.path()), binary, false).unwrap();
    let cfg = config_blocking(dir.path());
    assert_eq!(
        state(&cfg, binary),
        HookState::Stale {
            command: "/x/moat".into()
        }
    );
    let rendered = render(
        &cfg,
        binary,
        &fs::read_to_string(&cfg.settings_path).unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(rendered.contains("\"onFailure\": \"block\""), "{rendered}");
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Updated);
    assert_eq!(on_failure(&cfg, "PreToolUse"), "block");
    assert_eq!(state(&cfg, binary), HookState::Installed);
}

#[test]
fn on_failure_already_written_is_kept_when_the_version_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let binary = Path::new("/x/moat");
    install(&config_blocking(dir.path()), binary, false).unwrap();
    let cfg = config(dir.path());
    assert_eq!(state(&cfg, binary), HookState::Installed);
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
    let moved = Path::new("/usr/local/bin/moat");
    assert_eq!(install(&cfg, moved, false).unwrap(), Outcome::Updated);
    assert_eq!(on_failure(&cfg, "PreToolUse"), "block");
}

#[test]
fn remove_takes_on_failure_with_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_blocking(dir.path());
    fs::write(&cfg.settings_path, r#"{"theme":"dark"}"#).unwrap();
    install(&cfg, Path::new("/x/moat"), false).unwrap();
    let mut doc = root(&cfg);
    assert!(remove(&mut doc, &cfg));
    assert_eq!(doc, json!({"theme": "dark"}));
}

#[test]
fn codex_and_cursor_never_get_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let codex = HostConfig {
        host: Host::Codex,
        settings_path: dir.path().join("hooks.json"),
        dir: dir.path().to_path_buf(),
        hooks: &SPECS[..1],
        format: HookFormat::Nested,
        blocks_on_failure: || false,
    };
    install(&codex, Path::new("/x/moat"), false).unwrap();
    assert_eq!(on_failure(&codex, "PreToolUse"), Value::Null);
    let cursor = HostConfig {
        format: HookFormat::Cursor,
        blocks_on_failure: || true,
        settings_path: dir.path().join("cursor-hooks.json"),
        ..codex
    };
    install(&cursor, Path::new("/x/moat"), false).unwrap();
    let entry = &root(&cursor)["hooks"]["PreToolUse"][0];
    assert_eq!(entry["failClosed"], true);
    assert!(entry.get("onFailure").is_none());
    assert!(!lacks_on_failure(&cursor));
}

#[test]
fn cursor_format_sets_version_fail_closed_and_a_quoted_command() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HostConfig {
        host: Host::Cursor,
        settings_path: dir.path().join("hooks.json"),
        dir: dir.path().to_path_buf(),
        hooks: &[HookSpec {
            event: "beforeShellExecution",
            matcher: "",
            timeout: 600,
            block_on_failure: false,
        }],
        format: HookFormat::Cursor,
        blocks_on_failure: || false,
    };
    let binary = Path::new("/Applications/My Tools/moat");
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
    assert_eq!(state(&cfg, binary), HookState::Installed);
    let doc = root(&cfg);
    assert_eq!(doc["version"], 1);
    let entry = &doc["hooks"]["beforeShellExecution"][0];
    assert_eq!(
        entry["command"],
        "\"/Applications/My Tools/moat\" guard --host cursor"
    );
    assert_eq!(entry["failClosed"], true);
    assert_eq!(entry["timeout"], 600);
    assert!(entry.get("args").is_none());
    let moved = Path::new("/usr/local/bin/moat");
    assert_eq!(
        state(&cfg, moved),
        HookState::Stale {
            command: "/Applications/My Tools/moat".into()
        }
    );
    assert_eq!(install(&cfg, moved, false).unwrap(), Outcome::Updated);
    assert_eq!(
        root(&cfg)["hooks"]["beforeShellExecution"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

fn root(cfg: &HostConfig) -> Value {
    serde_json::from_str(&fs::read_to_string(&cfg.settings_path).unwrap()).unwrap()
}

#[test]
fn installs_every_event_idempotently_and_preserves_other_settings() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(
        &cfg.settings_path,
        r#"{"theme":"dark","hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[]}]}}"#,
    )
    .unwrap();
    let binary = Path::new("/opt/moat/bin/moat");

    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Unchanged);
    assert_eq!(state(&cfg, binary), HookState::Installed);

    let moved = Path::new("/usr/local/bin/moat");
    assert_eq!(
        state(&cfg, moved),
        HookState::Stale {
            command: "/opt/moat/bin/moat".into()
        }
    );
    assert_eq!(install(&cfg, moved, false).unwrap(), Outcome::Updated);

    let root = root(&cfg);
    assert_eq!(root["theme"], "dark");
    assert_eq!(root["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
    let pre = root["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1, "no duplicates after three installs");
    assert_eq!(pre[0]["hooks"][0]["command"], "/usr/local/bin/moat");
    assert_eq!(pre[0]["hooks"][0]["timeout"], 600);
    let cfg_change = root["hooks"]["ConfigChange"].as_array().unwrap();
    assert_eq!(cfg_change.len(), 1);
    assert_eq!(cfg_change[0]["matcher"], "user_settings");
    assert_eq!(cfg_change[0]["hooks"][0]["timeout"], 60);
    assert!(
        cfg.settings_path
            .with_extension("json.moat-backup")
            .exists()
    );
}

#[test]
fn install_keeps_the_first_backup_and_makes_a_deleted_one_again() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let original = r#"{"theme":"dark"}"#;
    fs::write(&cfg.settings_path, original).unwrap();
    let backup = cfg.settings_path.with_extension("json.moat-backup");

    install(&cfg, Path::new("/opt/moat/bin/moat"), false).unwrap();
    install(&cfg, Path::new("/usr/local/bin/moat"), false).unwrap();
    assert_eq!(
        fs::read_to_string(&backup).unwrap(),
        original,
        "a later edit keeps the copy from before OpenMoat"
    );
    let recorded = super::super::Recorded::load(&state_home(&cfg)).unwrap();
    assert_eq!(recorded.backups, std::slice::from_ref(&backup));

    fs::remove_file(&backup).unwrap();
    let edited = fs::read_to_string(&cfg.settings_path).unwrap();
    install(&cfg, Path::new("/opt/moat/bin/moat"), false).unwrap();
    assert_eq!(fs::read_to_string(&backup).unwrap(), edited);
}

#[test]
fn remove_undoes_install_and_keeps_foreign_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let original = json!({"theme": "dark", "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "lint.sh"}]}
    ], "Stop": []}});
    fs::write(&cfg.settings_path, original.to_string()).unwrap();
    install(&cfg, Path::new("/x/moat"), false).unwrap();
    let mut doc = root(&cfg);
    assert!(remove(&mut doc, &cfg));
    assert_eq!(doc, original);
    assert!(!remove(&mut doc, &cfg), "nothing left to remove");

    let created = tempfile::tempdir().unwrap();
    let cursor = HostConfig {
        host: Host::Cursor,
        settings_path: created.path().join("hooks.json"),
        dir: created.path().to_path_buf(),
        hooks: &SPECS[..1],
        format: HookFormat::Cursor,
        blocks_on_failure: || true,
    };
    install(&cursor, Path::new("/x/moat"), false).unwrap();
    let mut doc = root(&cursor);
    assert!(remove(&mut doc, &cursor));
    assert_eq!(doc, json!({}), "a file init created strips to nothing");
}

#[test]
fn a_missing_event_entry_is_stale_not_installed() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let binary = Path::new("/x/moat");
    install(&cfg, binary, false).unwrap();
    let mut root = root(&cfg);
    root["hooks"]
        .as_object_mut()
        .unwrap()
        .remove("ConfigChange");
    fs::write(&cfg.settings_path, root.to_string()).unwrap();
    assert!(matches!(state(&cfg, binary), HookState::Stale { .. }));
    assert_eq!(install(&cfg, binary, false).unwrap(), Outcome::Installed);
    assert_eq!(state(&cfg, binary), HookState::Installed);
}

#[test]
fn dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    assert_eq!(
        install(&cfg, Path::new("/x/moat"), true).unwrap(),
        Outcome::Installed
    );
    assert!(!cfg.settings_path.exists());
    assert_eq!(state(&cfg, Path::new("/x/moat")), HookState::Missing);
}

#[test]
fn foreign_entries_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(
        &cfg.settings_path,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"lint.sh"}]}]}}"#,
    )
    .unwrap();
    install(&cfg, Path::new("/x/moat"), false).unwrap();
    let pre = root(&cfg)["hooks"]["PreToolUse"].clone();
    let pre = pre.as_array().unwrap();
    assert_eq!(pre.len(), 2);
    assert_eq!(pre[0]["hooks"][0]["command"], "lint.sh");
}

#[test]
fn malformed_files_are_reported_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(&cfg.settings_path, "{ not json").unwrap();
    assert!(install(&cfg, Path::new("/x/moat"), false).is_err());
    assert!(matches!(
        state(&cfg, Path::new("/x/moat")),
        HookState::Unreadable(_)
    ));
    assert_eq!(
        fs::read_to_string(&cfg.settings_path).unwrap(),
        "{ not json"
    );
}
