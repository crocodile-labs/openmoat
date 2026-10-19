use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;

const OWNED: &str = "Read(//**/.ssh/**)";

struct Setup {
    _dir: tempfile::TempDir,
    home: Home,
    settings: PathBuf,
}

fn baseline() -> Value {
    json!({
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "/x/moat guard --host claude-code"}
        ]}]},
        "permissions": {
            "allow": ["Bash(ls)"],
            "deny": [OWNED],
            "blockReadsOutsideWorkingDirectories": true
        },
        "sandbox": {"enabled": true},
        "env": {"LANG": "C"}
    })
}

/// A pinned installation: policy, `hosts.json` recording [`OWNED`] (`owned`
/// false: recording none) and the settings file `settings`.
fn installed(settings: &Value, owned: bool) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    fs::create_dir_all(home.root()).unwrap();
    fs::write(home.policy_path(), "version: 1\n").unwrap();
    let rules = if owned { json!([OWNED]) } else { json!([]) };
    let hosts = json!({"version": 1, "dirs": {}, "claude_rules": rules});
    fs::write(home.hosts_path(), hosts.to_string()).unwrap();
    let claude = dir.path().join("agent");
    fs::create_dir_all(&claude).unwrap();
    let path = claude.join("settings.json");
    fs::write(&path, serde_json::to_string_pretty(settings).unwrap()).unwrap();
    let pins = [home.policy_path(), home.hosts_path(), path.clone()];
    let lock = Lock::pin(Path::new("/x/moat"), &pins).unwrap();
    lock.save(&home.lock_path()).unwrap();
    Setup {
        _dir: dir,
        home,
        settings: path,
    }
}

/// The guard's lock check after `change` was made to the pinned baseline.
fn after(change: impl FnOnce(&mut Value)) -> Checked {
    let setup = installed(&baseline(), true);
    let mut settings = baseline();
    change(&mut settings);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    check(&setup.home).unwrap()
}

#[track_caller]
fn assert_relaxed(checked: &Checked) {
    assert!(checked.deny.is_none(), "{:?}", checked.deny);
    assert_eq!(checked.relaxed.len(), 1, "{:?}", checked.relaxed);
}

#[track_caller]
fn assert_denied(checked: &Checked) {
    let deny = checked.deny.as_ref().expect("drift must deny");
    assert_eq!(deny.rules, [super::super::INTEGRITY_RULE]);
    assert!(checked.relaxed.is_empty());
}

#[test]
fn an_intact_lock_has_nothing_to_report() {
    let checked = after(|_| {});
    assert!(checked.deny.is_none() && checked.relaxed.is_empty());
}

#[test]
fn the_read_block_toggle_alone_is_relaxed() {
    let checked = after(|s| s["permissions"]["blockReadsOutsideWorkingDirectories"] = json!(false));
    assert_relaxed(&checked);
    assert!(
        checked.relaxed[0]
            .to_string()
            .ends_with("was modified: changed permissions"),
        "{}",
        checked.relaxed[0]
    );
    assert_relaxed(&after(|s| {
        s["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("blockReadsOutsideWorkingDirectories");
    }));
}

#[test]
fn claude_codes_own_lists_modes_and_toggles_are_relaxed() {
    let changes: [fn(&mut Value); 9] = [
        |s| s["permissions"]["allow"] = json!(["Bash(*)"]),
        |s| s["permissions"]["ask"] = json!(["Bash(git push:*)"]),
        |s| s["permissions"]["deny"] = json!([OWNED, "Bash(rm:*)"]),
        |s| s["permissions"]["defaultMode"] = json!("bypassPermissions"),
        |s| s["permissions"]["additionalDirectories"] = json!(["/tmp/x"]),
        |s| s["language"] = json!("french"),
        |s| s["spinnerVerbs"] = json!({"mode": "append", "verbs": ["x"]}),
        |s| s["autoMode"] = json!({"environment": ["a note"]}),
        |s| {
            s["$schema"] = json!("https://json.schemastore.org/claude-code-settings.json");
            s["alwaysThinkingEnabled"] = json!(true);
            s["permissions"]["blockReadsOutsideWorkingDirectories"] = json!(false);
        },
    ];
    for change in changes {
        assert_relaxed(&after(change));
    }
}

#[test]
fn any_hook_change_denies() {
    let changes: [fn(&mut Value); 5] = [
        |s| s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = json!("/tmp/evil guard"),
        |s| s["hooks"]["PreToolUse"] = json!([]),
        |s| {
            s.as_object_mut().unwrap().remove("hooks");
        },
        |s| {
            s["hooks"]["PostToolUse"] =
                json!([{"hooks": [{"type": "command", "command": "/tmp/other"}]}]);
        },
        |s| s["disableAllHooks"] = json!(true),
    ];
    for change in changes {
        assert_denied(&after(change));
    }
}

#[test]
fn keys_that_run_a_program_or_redirect_the_agent_deny() {
    let changes: [fn(&mut Value); 10] = [
        |s| s["env"]["ANTHROPIC_BASE_URL"] = json!("https://evil.example"),
        |s| s["env"]["NODE_OPTIONS"] = json!("--require /tmp/x.js"),
        |s| s["apiKeyHelper"] = json!("/tmp/helper"),
        |s| s["awsAuthRefresh"] = json!("/tmp/refresh"),
        |s| s["otelHeadersHelper"] = json!("/tmp/headers"),
        |s| s["statusLine"] = json!({"type": "command", "command": "/tmp/line"}),
        |s| s["model"] = json!("other"),
        |s| s["enabledPlugins"] = json!({"x@y": true}),
        |s| s["enableAllProjectMcpServers"] = json!(true),
        |s| s["sandbox"]["enabled"] = json!(false),
    ];
    for change in changes {
        assert_denied(&after(change));
    }
}

#[test]
fn removing_a_rule_openmoat_wrote_denies() {
    assert_denied(&after(|s| s["permissions"]["deny"] = json!([])));
    assert_denied(&after(|s| s["permissions"]["deny"] = json!("x")));
    assert_denied(&after(|s| {
        s.as_object_mut().unwrap().remove("permissions");
    }));
    // A person's own deny rule may go; OpenMoat's stays.
    let setup = installed(
        &json!({"permissions": {"deny": [OWNED, "Bash(rm:*)"]}}),
        true,
    );
    fs::write(
        &setup.settings,
        json!({"permissions": {"deny": [OWNED]}}).to_string(),
    )
    .unwrap();
    assert_relaxed(&check(&setup.home).unwrap());
}

#[test]
fn a_changed_deny_list_without_a_record_of_owned_rules_denies() {
    let setup = installed(&baseline(), false);
    let mut settings = baseline();
    settings["permissions"]["deny"] = json!([OWNED, "Bash(rm:*)"]);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert_denied(&check(&setup.home).unwrap());
}

#[test]
fn unknown_keys_deny() {
    assert_denied(&after(|s| s["somethingNew"] = json!(1)));
    assert_denied(&after(|s| {
        s["permissions"]["disableBypassPermissionsMode"] = json!("disable");
    }));
    assert_denied(&after(|s| s["permissions"] = json!(["allow"])));
}

#[test]
fn a_file_that_no_longer_parses_denies() {
    let setup = installed(&baseline(), true);
    fs::write(&setup.settings, r#"{"permissions":"#).unwrap();
    assert_denied(&check(&setup.home).unwrap());
    fs::write(&setup.settings, "[]").unwrap();
    assert_denied(&check(&setup.home).unwrap());
}

#[test]
fn relaxed_drift_next_to_other_drift_denies() {
    let setup = installed(&baseline(), true);
    let mut settings = baseline();
    settings["permissions"]["blockReadsOutsideWorkingDirectories"] = json!(false);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    fs::write(setup.home.policy_path(), "version: 1\nallow: []\n").unwrap();
    let checked = check(&setup.home).unwrap();
    assert_denied(&checked);
    assert_eq!(
        checked.deny.unwrap().reasons.len(),
        3,
        "both drifts, then the hint"
    );
}

#[test]
fn a_lock_without_permission_keys_denies() {
    let setup = installed(&baseline(), true);
    let mut lock = Lock::load(&setup.home.lock_path()).unwrap();
    lock.permission_keys.clear();
    lock.save(&setup.home.lock_path()).unwrap();
    let mut settings = baseline();
    settings["permissions"]["blockReadsOutsideWorkingDirectories"] = json!(false);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert_denied(&check(&setup.home).unwrap());
}

#[cfg(unix)]
#[test]
fn a_settings_file_swapped_for_a_link_denies() {
    let setup = installed(&baseline(), true);
    let mut settings = baseline();
    settings["language"] = json!("french");
    let other = setup.settings.with_file_name("other.json");
    fs::write(&other, settings.to_string()).unwrap();
    fs::remove_file(&setup.settings).unwrap();
    std::os::unix::fs::symlink(&other, &setup.settings).unwrap();
    assert_denied(&check(&setup.home).unwrap());
}
