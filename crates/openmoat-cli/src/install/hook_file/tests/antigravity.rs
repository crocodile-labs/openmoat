use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::super::{HookState, Outcome, install, remove, state};
use crate::home::Home;
use crate::install::HostConfig;

fn config(dir: &Path) -> HostConfig {
    let spec = Host::AntigravityCli.spec().install.as_ref().unwrap();
    HostConfig {
        host: Host::AntigravityCli,
        settings_path: dir.join("hooks.json"),
        dir: dir.to_path_buf(),
        hooks: spec.hooks,
        layout: spec.hook_file,
        blocks_on_failure: || false,
        state_dir: std::path::PathBuf::from("/h/state"),
    }
}

/// `init` writes one named entry beside the person's own hooks, and
/// `uninstall` takes away only it; the file holds no empty entry after.
#[test]
fn the_named_entry_is_installed_once_and_removed_alone() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let theirs = json!({ "lint": { "enabled": true, "PostToolUse": [] } });
    std::fs::write(&config.settings_path, theirs.to_string()).unwrap();
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/opt/open moat/openmoat");
    assert_eq!(state(&config, binary), HookState::Missing);
    assert_eq!(
        install(&home, &config, binary, false).unwrap(),
        Outcome::Installed
    );
    assert_eq!(
        install(&home, &config, binary, false).unwrap(),
        Outcome::Unchanged
    );
    assert_eq!(state(&config, binary), HookState::Installed);
    let text = std::fs::read_to_string(&config.settings_path).unwrap();
    let mut root: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(root["openmoat"]["enabled"], true, "{root}");
    assert_eq!(root["lint"], theirs["lint"]);
    let command = root["openmoat"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        command.contains(" guard --host antigravity-cli --home /h/state"),
        "{command}"
    );
    assert!(remove(&mut root, &config));
    assert_eq!(root, theirs);
}

/// `enabled: false` on our entry never runs the hook: the state says so, by
/// name, and `init` turns it back on.
#[test]
fn a_switched_off_entry_is_turned_off_state_and_init_repairs_it() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/usr/bin/openmoat");
    install(&home, &config, binary, false).unwrap();
    let mut root: Value =
        serde_json::from_str(&std::fs::read_to_string(&config.settings_path).unwrap()).unwrap();
    root["openmoat"]["enabled"] = json!(false);
    std::fs::write(&config.settings_path, root.to_string()).unwrap();
    match state(&config, binary) {
        HookState::TurnedOff(why) => {
            assert!(why.contains("switched off"), "{why}");
            assert!(why.contains("Antigravity CLI"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(config.layout.entries().unwrap().turned_off(&root));
    assert_eq!(
        install(&home, &config, binary, false).unwrap(),
        Outcome::Updated
    );
    assert_eq!(state(&config, binary), HookState::Installed);
}
