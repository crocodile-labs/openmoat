//! Gemini CLI's `settings.json`: a new model, theme, sign-in method or display
//! toggle is decided through; every other change, the attacks among them,
//! denies every call.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::listed;
use crate::home::Home;
use crate::integrity::{INTEGRITY_RULE, Lock, check};

struct Setup {
    _dir: tempfile::TempDir,
    home: Home,
    settings: PathBuf,
}

/// The settings as `openmoat init` leaves them, with the person's own choices.
fn baseline() -> Value {
    json!({
        "model": {"name": "gemini-2.5-pro"},
        "ui": {"theme": "GitHub", "footer": {"hideCWD": false}},
        "security": {"auth": {"selectedType": "oauth-personal"}},
        "general": {"vimMode": false},
        "tools": {"sandbox": true, "exclude": ["run_shell_command(rm)"]},
        "mcpServers": {},
        "hooksConfig": {"enabled": true},
        "hooks": {"BeforeTool": [{"matcher": "*", "hooks": [{
            "name": "openmoat", "type": "command",
            "command": "'/x/openmoat' guard --host gemini-cli", "timeout": 600_000
        }]}]}
    })
}

/// A pinned installation: policy, `hosts.json` and `settings` at
/// `<home>/.gemini/settings.json`.
fn installed(settings: &Value) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    fs::create_dir_all(home.root()).unwrap();
    fs::write(home.policy_path(), "version: 1\n").unwrap();
    fs::write(home.hosts_path(), r#"{"version": 1, "dirs": {}}"#).unwrap();
    let gemini = dir.path().join("user/.gemini");
    fs::create_dir_all(&gemini).unwrap();
    let path = gemini.join("settings.json");
    fs::write(&path, serde_json::to_string_pretty(settings).unwrap()).unwrap();
    let pins = [home.policy_path(), home.hosts_path(), path.clone()];
    Lock::pin(Path::new("/x/openmoat"), &pins)
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    Setup {
        _dir: dir,
        home,
        settings: path,
    }
}

/// Whether the guard keeps deciding after `change` to the pinned baseline.
fn decided_after(change: impl FnOnce(&mut Value)) -> bool {
    let setup = installed(&baseline());
    let mut settings = baseline();
    change(&mut settings);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    decided(&setup)
}

/// Whether the guard keeps deciding: no deny, and the drift reported.
fn decided(setup: &Setup) -> bool {
    let checked = check(&setup.home).unwrap().checked;
    if let Some(deny) = checked.deny {
        assert_eq!(deny.rules, [INTEGRITY_RULE]);
        assert!(checked.relaxed.is_empty());
        false
    } else {
        assert_eq!(checked.relaxed.len(), 1, "{:?}", checked.relaxed);
        true
    }
}

#[test]
fn gemini_settings_are_found_by_their_place() {
    assert!(listed(Path::new("/home/me/.gemini/settings.json")).is_some());
    assert!(listed(Path::new("/srv/agent-home/.gemini/settings.json")).is_some());
    for other in [
        "/home/me/.claude/settings.json",
        "/home/me/.gemini/settings.json.bak",
        "/home/me/gemini/settings.json",
        "/home/me/.gemini/extensions/x/settings.json",
    ] {
        assert!(listed(Path::new(other)).is_none(), "{other}");
    }
}

#[test]
fn a_new_model_alone_is_decided_through() {
    assert!(decided_after(
        |s| s["model"]["name"] = json!("gemini-2.5-flash")
    ));
}

#[test]
fn a_new_theme_alone_is_decided_through() {
    assert!(decided_after(|s| s["ui"]["theme"] = json!("Dracula")));
}

#[test]
fn sign_in_choices_and_display_toggles_are_decided_through() {
    let changes: [fn(&mut Value); 6] = [
        |s| s["security"]["auth"]["selectedType"] = json!("gemini-api-key"),
        // `/auth signout` removes the choice
        |s| {
            s["security"]["auth"]
                .as_object_mut()
                .unwrap()
                .remove("selectedType");
        },
        |s| s["ui"]["hideTips"] = json!(true),
        |s| s["ui"]["footer"]["hideCWD"] = json!(true),
        |s| s["general"]["vimMode"] = json!(true),
        // all of them in one save, and a key first written into a new object
        |s| {
            s["model"]["name"] = json!("gemini-2.5-flash");
            s["ui"]["theme"] = json!("ANSI");
            s["ui"]["accessibility"] = json!({"screenReader": true});
            s["ide"] = json!({"hasSeenNudge": true});
        },
    ];
    for change in changes {
        assert!(decided_after(change));
    }
}

#[test]
fn a_hook_added_removed_or_turned_off_denies() {
    let changes: [fn(&mut Value); 5] = [
        |s| {
            s["hooks"]["BeforeTool"].as_array_mut().unwrap().push(
                json!({"matcher": "*", "hooks": [{"type": "command", "command": "/tmp/rewrite"}]}),
            );
        },
        |s| {
            s["hooks"]["SessionStart"] =
                json!([{"hooks": [{"type": "command", "command": "/tmp/x"}]}]);
        },
        |s| {
            s.as_object_mut().unwrap().remove("hooks");
        },
        |s| s["hooksConfig"]["enabled"] = json!(false),
        |s| s["hooksConfig"]["disabled"] = json!(["openmoat"]),
    ];
    for change in changes {
        assert!(!decided_after(change));
    }
}

#[test]
fn mcp_sandbox_and_tool_changes_deny() {
    let changes: [fn(&mut Value); 5] = [
        |s| s["mcpServers"]["evil"] = json!({"command": "/tmp/server"}),
        |s| s["tools"]["sandbox"] = json!(false),
        |s| s["tools"]["exclude"] = json!([]),
        |s| s["tools"]["discoveryCommand"] = json!("/tmp/tools"),
        |s| s["security"]["folderTrust"] = json!({"enabled": false}),
    ];
    for change in changes {
        assert!(!decided_after(change));
    }
}

#[test]
fn keys_not_on_the_list_deny() {
    let changes: [fn(&mut Value); 7] = [
        |s| s["somethingNew"] = json!(true),
        |s| s["general"]["preferredEditor"] = json!("/tmp/editor"),
        |s| s["ui"]["escapePastedAtSymbols"] = json!(false),
        |s| s["security"]["auth"]["enforcedType"] = json!("vertex-ai"),
        |s| s["advanced"] = json!({"excludedEnvVars": []}),
        |s| s["context"] = json!({"includeDirectories": ["/"]}),
        // Claude Code's own relaxed keys are not Gemini CLI's
        |s| s["language"] = json!("french"),
    ];
    for change in changes {
        assert!(!decided_after(change));
    }
}

#[test]
fn a_relaxed_key_of_another_shape_denies() {
    let changes: [fn(&mut Value); 4] = [
        |s| s["model"]["name"] = json!({"command": "/tmp/x"}),
        |s| s["ui"]["theme"] = json!(["Dracula"]),
        |s| s["ui"]["hideTips"] = json!("yes"),
        |s| s["model"] = json!("gemini-2.5-flash"),
    ];
    for change in changes {
        assert!(!decided_after(change));
    }
}

#[test]
fn a_theme_change_next_to_a_hook_change_denies() {
    assert!(!decided_after(|s| {
        s["ui"]["theme"] = json!("Dracula");
        s["hooksConfig"]["enabled"] = json!(false);
    }));
    assert!(!decided_after(|s| {
        s["model"]["name"] = json!("gemini-2.5-flash");
        s["mcpServers"]["evil"] = json!({"command": "/tmp/server"});
    }));
}

#[test]
fn a_file_that_no_longer_parses_denies() {
    let setup = installed(&baseline());
    fs::write(&setup.settings, r#"{"model": {"name": "x"}"#).unwrap();
    assert!(!decided(&setup));
    // Gemini CLI reads comments; OpenMoat does not, so they deny too.
    let mut text = baseline().to_string();
    text.insert_str(1, "// a note\n");
    fs::write(&setup.settings, text).unwrap();
    assert!(!decided(&setup));
}

#[test]
fn a_relaxed_change_next_to_other_drift_denies() {
    let setup = installed(&baseline());
    let mut settings = baseline();
    settings["ui"]["theme"] = json!("Dracula");
    fs::write(&setup.settings, settings.to_string()).unwrap();
    fs::write(setup.home.policy_path(), "version: 1\ndefaults: {}\n").unwrap();
    assert!(!decided(&setup));
}

#[test]
fn a_lock_without_the_rest_digest_denies() {
    let setup = installed(&baseline());
    let mut lock = Lock::load(&setup.home.lock_path()).unwrap();
    assert_eq!(lock.relaxed_rest.len(), 1);
    lock.relaxed_rest.clear();
    lock.save(&setup.home.lock_path()).unwrap();
    let mut settings = baseline();
    settings["model"]["name"] = json!("gemini-2.5-flash");
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert!(!decided(&setup));
}

#[cfg(unix)]
#[test]
fn a_settings_file_swapped_for_a_link_denies() {
    let setup = installed(&baseline());
    let mut settings = baseline();
    settings["model"]["name"] = json!("gemini-2.5-flash");
    let elsewhere = setup.settings.with_file_name("real.json");
    fs::write(&elsewhere, settings.to_string()).unwrap();
    fs::remove_file(&setup.settings).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &setup.settings).unwrap();
    assert!(!decided(&setup));
}
