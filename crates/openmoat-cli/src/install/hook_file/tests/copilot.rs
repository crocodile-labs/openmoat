use std::fs;
use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::home::Home;
use crate::install::HostConfig;
use crate::install::hook_file::{HookState, Outcome, install, remove, state};

/// GitHub Copilot CLI as its spec installs it, in a scratch `COPILOT_HOME`.
fn config(dir: &Path) -> HostConfig {
    let install = Host::CopilotCli.spec().install.as_ref().unwrap();
    HostConfig {
        host: Host::CopilotCli,
        settings_path: dir.join(install.config_file),
        dir: dir.to_path_buf(),
        hooks: install.hooks,
        layout: install.hook_file,
        blocks_on_failure: || false,
        state_dir: std::path::PathBuf::from("/h/.moat"),
    }
}

fn root(cfg: &HostConfig) -> Value {
    serde_json::from_str(&fs::read_to_string(&cfg.settings_path).unwrap()).unwrap()
}

#[test]
fn writes_a_hook_file_of_its_own_with_a_command_per_shell() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    assert_eq!(format!("{:?}", cfg.layout), "Entries(Copilot)");
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/Users/o'neil/bin/openmoat");
    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Installed
    );
    assert!(cfg.settings_path.ends_with("hooks/openmoat.json"));
    // `postToolUse` reports what a call returned (ADR-063). The payloads name
    // no event, so each entry names its own.
    let entry = |event: &str, timeout: u64| {
        json!([{
            "type": "command",
            "bash": format!(r"'/Users/o'\''neil/bin/openmoat' guard --host copilot-cli --home /h/.moat --event {event}"),
            "powershell": format!("& '/Users/o''neil/bin/openmoat' guard --host copilot-cli --home /h/.moat --event {event}"),
            "timeoutSec": timeout,
        }])
    };
    assert_eq!(
        root(&cfg),
        json!({
            "version": 1,
            "hooks": {
                "preToolUse": entry("preToolUse", 600),
                "postToolUse": entry("postToolUse", 60),
            },
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

/// An entry from before `--event` is still OpenMoat's (its payloads are decided
/// as calls), and stale until `init` rewrites it with the flag.
#[test]
fn an_entry_without_its_event_is_stale_until_init_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/x/openmoat");
    install(&home, &cfg, binary, false).unwrap();
    let mut doc = root(&cfg);
    for shell in ["bash", "powershell"] {
        let command = doc["hooks"]["preToolUse"][0][shell].as_str().unwrap();
        let old = command.replace(" --event preToolUse", "");
        doc["hooks"]["preToolUse"][0][shell] = old.into();
    }
    doc["hooks"].as_object_mut().unwrap().remove("postToolUse");
    fs::write(&cfg.settings_path, doc.to_string()).unwrap();
    assert!(matches!(state(&cfg, binary), HookState::Stale { .. }));
    assert_eq!(
        install(&home, &cfg, binary, false).unwrap(),
        Outcome::Installed
    );
    assert_eq!(state(&cfg, binary), HookState::Installed);
    let hooks = &root(&cfg)["hooks"];
    assert_eq!(hooks["preToolUse"].as_array().unwrap().len(), 1, "{hooks}");
    let bash = hooks["preToolUse"][0]["bash"].as_str().unwrap();
    assert!(bash.ends_with(" --event preToolUse"), "{bash}");
}
