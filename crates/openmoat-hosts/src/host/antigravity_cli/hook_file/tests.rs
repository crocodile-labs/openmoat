use serde_json::json;

use super::*;
use crate::contract::HookSpec as Spec;
use crate::wire::hook_file::HookOutcome;

const ID: &str = "antigravity-cli";

fn guard() -> GuardCommand {
    GuardCommand::new("/opt/open moat/openmoat").with_home("/h/.moat")
}

fn specs() -> Vec<Spec> {
    vec![Spec::new("PreToolUse", "*", 600, false)]
}

fn no_flag() -> bool {
    false
}

#[test]
fn install_writes_one_named_entry_and_is_idempotent() {
    let layout: &dyn HookFile = &Named;
    let mut root = json!({ "lint": { "enabled": true } });
    let first = layout
        .upsert(&mut root, "hooks.json", ID, &specs(), &guard(), no_flag)
        .unwrap();
    assert_eq!(first, HookOutcome::Installed);
    let again = layout
        .upsert(&mut root, "hooks.json", ID, &specs(), &guard(), no_flag)
        .unwrap();
    assert_eq!(again, HookOutcome::Unchanged);
    assert_eq!(root["openmoat"]["enabled"], true);
    assert_eq!(root["openmoat"]["PreToolUse"].as_array().unwrap().len(), 1);
    assert_eq!(root["lint"], json!({ "enabled": true }));
    assert_eq!(
        layout.state(&root, ID, &specs(), &guard(), no_flag),
        crate::wire::hook_file::HookFileState::Installed
    );
}

#[test]
fn a_switched_off_entry_is_reported_and_turned_back_on() {
    let layout: &dyn HookFile = &Named;
    let mut root = json!({});
    layout
        .upsert(&mut root, "hooks.json", ID, &specs(), &guard(), no_flag)
        .unwrap();
    root["openmoat"]["enabled"] = json!(false);
    assert!(layout.turned_off(&root));
    let outcome = layout
        .upsert(&mut root, "hooks.json", ID, &specs(), &guard(), no_flag)
        .unwrap();
    assert_eq!(outcome, HookOutcome::Updated);
    assert!(!layout.turned_off(&root));
    // Absent is on, the host's own default.
    root["openmoat"].as_object_mut().unwrap().remove("enabled");
    assert!(!layout.turned_off(&root));
}

#[test]
fn remove_takes_only_ours_and_leaves_no_empty_section() {
    let layout: &dyn HookFile = &Named;
    let mut root = json!({ "lint": { "enabled": true } });
    layout
        .upsert(&mut root, "hooks.json", ID, &specs(), &guard(), no_flag)
        .unwrap();
    assert!(layout.remove(&mut root, ID));
    assert_eq!(root, json!({ "lint": { "enabled": true } }));
    assert!(!layout.remove(&mut root, ID));
}

#[test]
fn commands_round_trip_and_other_hosts_are_not_ours() {
    for windows in [false, true] {
        let command = command_for(&guard(), ID, windows);
        assert_eq!(binary_of(&command, ID).as_deref(), Some("/opt/open moat/openmoat"));
    }
    assert_eq!(command_for(&guard(), ID, false), "'/opt/open moat/openmoat' guard --host antigravity-cli --home /h/.moat");
    let plain = GuardCommand::new("C:/bin/openmoat.exe");
    assert_eq!(command_for(&plain, ID, true), "C:/bin/openmoat.exe guard --host antigravity-cli");
    let other = json!({ "hooks": [{ "command": "'/b' guard --host codex" }] });
    assert!(!Named.is_ours(&other, ID));
}
