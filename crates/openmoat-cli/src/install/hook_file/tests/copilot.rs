use std::fs;
use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::home::Home;
use crate::install::hook_file::{HookState, Outcome, install, remove, state};
use crate::install::{HookFormat, HostConfig};

/// GitHub Copilot CLI as its spec installs it, in a scratch `COPILOT_HOME`.
fn config(dir: &Path) -> HostConfig {
    let install = Host::CopilotCli.spec().install.as_ref().unwrap();
    HostConfig {
        host: Host::CopilotCli,
        settings_path: dir.join(install.config_file),
        dir: dir.to_path_buf(),
        hooks: install.hooks,
        format: install.hook_format,
        blocks_on_failure: || false,
    }
}

fn root(cfg: &HostConfig) -> Value {
    serde_json::from_str(&fs::read_to_string(&cfg.settings_path).unwrap()).unwrap()
}

#[test]
fn writes_a_hook_file_of_its_own_with_a_command_per_shell() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    assert_eq!(cfg.format, HookFormat::Copilot);
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/Users/o'neil/bin/openmoat");
    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Installed
    );
    assert!(cfg.settings_path.ends_with("hooks/openmoat.json"));
    assert_eq!(
        root(&cfg),
        json!({
            "version": 1,
            "hooks": {"preToolUse": [{
                "type": "command",
                "bash": r"'/Users/o'\''neil/bin/openmoat' guard --host copilot-cli",
                "powershell": "& '/Users/o''neil/bin/openmoat' guard --host copilot-cli",
                "timeoutSec": 600,
            }]},
        })
    );
    assert_eq!(state(&cfg, binary), HookState::Installed);
    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Unchanged
    );
    let moved = Path::new("/usr/local/bin/openmoat");
    assert_eq!(
        state(&cfg, moved),
        HookState::Stale {
            command: binary.to_string_lossy().into_owned()
        }
    );
    assert_eq!(
        install(&home, &cfg, moved, false).unwrap(),
        Outcome::Updated
    );
    assert_eq!(
        root(&cfg)["hooks"]["preToolUse"].as_array().unwrap().len(),
        1
    );
}

/// `uninstall` takes out the entry and the `version` it added, leaving `{}`,
/// which it deletes; another hook in the file stays.
#[test]
fn removing_leaves_nothing_of_ours_and_keeps_other_hooks() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let home = Home::at(dir.path().join("state"));
    install(&home, &cfg, Path::new("/x/openmoat"), false).unwrap();
    let mut doc = root(&cfg);
    assert!(remove(&mut doc, &cfg));
    assert_eq!(doc, json!({}));
    let mut shared = json!({"version": 1, "hooks": {"preToolUse": [
        {"type": "command", "bash": "./audit.sh"},
        root(&cfg)["hooks"]["preToolUse"][0].clone(),
    ]}});
    assert!(remove(&mut shared, &cfg));
    assert_eq!(
        shared,
        json!({"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./audit.sh"}]}})
    );
    assert!(!remove(&mut shared, &cfg));
}
