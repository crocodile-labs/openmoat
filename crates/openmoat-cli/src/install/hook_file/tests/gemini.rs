use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::super::{HookState, Outcome, install, remove, state};
use crate::home::Home;
use crate::install::HostConfig;

/// `init` writes one named `BeforeTool` entry with the timeout in
/// milliseconds, beside the person's own hooks and settings, and `uninstall`
/// takes away only it.
#[test]
fn the_entry_is_installed_once_and_removed_alone() {
    let dir = tempfile::tempdir().unwrap();
    let spec = Host::GeminiCli.spec().install.as_ref().unwrap();
    let config = HostConfig {
        host: Host::GeminiCli,
        settings_path: dir.path().join("settings.json"),
        dir: dir.path().to_path_buf(),
        hooks: spec.hooks,
        layout: spec.hook_file,
        blocks_on_failure: || false,
    };
    let theirs = json!({
        "ui": {"theme": "GitHub"},
        "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [
            {"type": "command", "command": "node lint.js"}
        ]}]}
    });
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
    let ours = &root["hooks"]["BeforeTool"][1];
    assert_eq!(ours["matcher"], "*");
    assert_eq!(ours["hooks"][0]["name"], "openmoat");
    assert_eq!(ours["hooks"][0]["type"], "command");
    assert_eq!(ours["hooks"][0]["timeout"], 600_000);
    assert!(
        ours["hooks"][0]["command"]
            .as_str()
            .unwrap()
            // PowerShell adds `; if (-not $?) { exit 2 }` on Windows
            .contains(" guard --host gemini-cli")
    );
    assert_eq!(
        state(&config, Path::new("/usr/bin/openmoat")),
        HookState::Stale {
            command: "/opt/open moat/openmoat".into()
        }
    );
    assert!(remove(&mut root, &config));
    assert_eq!(root, theirs);
}
