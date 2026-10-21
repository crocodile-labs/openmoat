use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::super::{HookState, Outcome, install, remove, state};
use super::{binary_of, command_for};
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
        format: spec.hook_format,
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
            .ends_with(" guard --host gemini-cli")
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

#[test]
fn the_binary_is_quoted_for_the_shell_and_read_back() {
    let id = "gemini-cli";
    let posix = command_for("/Users/me/My Tools/it's/openmoat", id, false);
    assert_eq!(
        posix,
        r"'/Users/me/My Tools/it'\''s/openmoat' guard --host gemini-cli"
    );
    assert_eq!(
        binary_of(&posix, id).as_deref(),
        Some("/Users/me/My Tools/it's/openmoat")
    );
    let windows = command_for(r"C:\Program Files\it's\openmoat.exe", id, true);
    assert_eq!(
        windows,
        r"& 'C:\Program Files\it''s\openmoat.exe' guard --host gemini-cli; if (-not $?) { exit 2 }"
    );
    assert_eq!(
        binary_of(&windows, id).as_deref(),
        Some(r"C:\Program Files\it's\openmoat.exe")
    );
    assert_eq!(
        binary_of("/usr/bin/openmoat guard --host gemini-cli", id).as_deref(),
        Some("/usr/bin/openmoat")
    );
    let doubled = command_for("/opt/a''b/openmoat", id, false);
    assert_eq!(
        binary_of(&doubled, id).as_deref(),
        Some("/opt/a''b/openmoat")
    );
    assert_eq!(binary_of("'/x/openmoat' guard --host cursor", id), None);
    assert_eq!(binary_of("node .gemini/hooks/check.js", id), None);
}
