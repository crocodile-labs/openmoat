use std::fs;
use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::super::{HookState, Outcome, install, remove, state};
use crate::home::Home;
use crate::install::HostConfig;

fn config(dir: &Path) -> HostConfig {
    let spec = Host::ClaudeCode.spec().install.as_ref().unwrap();
    HostConfig {
        host: Host::ClaudeCode,
        settings_path: dir.join("settings.json"),
        dir: dir.to_path_buf(),
        hooks: spec.hooks,
        layout: spec.hook_file,
        blocks_on_failure: |_| true,
        state_dir: std::path::PathBuf::from("/h/.moat"),
    }
}

fn read(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// `init` sends a file the person `@`-mentions through Claude Code's file
/// tools, so the hook decides its read, beside the person's own variables;
/// a file without the variable is stale until `init` runs again, and
/// `uninstall` gives back the person's file.
#[test]
fn file_mentions_go_through_the_hook_and_uninstall_takes_the_variable_away() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let home = Home::at(dir.path().join(".moat"));
    let binary = Path::new("/x/openmoat");
    let theirs = json!({"model": "opus", "env": {"DISABLE_AUTO_COMPACT": "1"}});
    fs::write(&cfg.settings_path, theirs.to_string()).unwrap();

    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Installed
    );
    let root = read(&cfg.settings_path);
    assert_eq!(root["env"]["CLAUDE_CODE_DISABLE_FILE_MENTIONS"], "1");
    assert_eq!(root["env"]["DISABLE_AUTO_COMPACT"], "1");
    assert_eq!(state(&cfg, binary), HookState::Installed);
    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Unchanged
    );

    // An install from before the variable, or one whose variable was taken
    // out or turned off, is stale.
    for value in [Value::Null, json!("0")] {
        let mut edited = read(&cfg.settings_path);
        edited["env"]["CLAUDE_CODE_DISABLE_FILE_MENTIONS"] = value;
        fs::write(&cfg.settings_path, edited.to_string()).unwrap();
        assert!(matches!(state(&cfg, binary), HookState::Stale { .. }));
        assert_eq!(
            install(&home, &cfg, binary, false).unwrap(),
            Outcome::Updated
        );
        assert_eq!(state(&cfg, binary), HookState::Installed);
    }

    let mut root = read(&cfg.settings_path);
    assert!(remove(&mut root, &cfg));
    assert_eq!(root, theirs);

    // `uninstall` takes the `env` block it created away whole.
    let mut fresh = json!({});
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    install(&Home::at(dir.path().join(".moat")), &cfg, binary, false).unwrap();
    let mut root = read(&cfg.settings_path);
    assert!(remove(&mut root, &cfg));
    assert_eq!(root, fresh.take());
}

/// An `env` that is not an object is reported, never overwritten.
#[test]
fn an_env_that_is_not_an_object_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(&cfg.settings_path, r#"{"env": "x"}"#).unwrap();
    let home = Home::at(dir.path().join(".moat"));
    assert!(install(&home, &cfg, Path::new("/x/openmoat"), false).is_err());
    assert_eq!(
        fs::read_to_string(&cfg.settings_path).unwrap(),
        r#"{"env": "x"}"#
    );
}
