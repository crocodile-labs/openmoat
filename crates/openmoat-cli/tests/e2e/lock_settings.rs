//! Self-protection of Claude Code's `settings.json`: drift in Claude Code's own
//! toggles, permission lists and model choice is reported but the guard keeps deciding; any
//! other drift (hooks, keys that run a program or redirect the agent, a removed
//! OpenMoat rule, an unknown key, a file that no longer parses) denies every call.

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::common::{OK, Sandbox, USAGE, fixture, json, text, verdict_and_reason};

const SESSION: &str = "7c1e4b2a";

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".claude"])
}

fn settings_path(sb: &Sandbox) -> PathBuf {
    sb.home.join(".claude/settings.json")
}

/// Apply `change` to the installed settings file, as a person or an agent would.
fn edit_settings(sb: &Sandbox, change: impl FnOnce(&mut Value)) {
    let mut settings: Value =
        serde_json::from_str(&std::fs::read_to_string(settings_path(sb)).unwrap()).unwrap();
    change(&mut settings);
    std::fs::write(settings_path(sb), settings.to_string()).unwrap();
}

/// The verdict and reason for the golden `Read src/lib.rs` payload.
fn read_src(sb: &Sandbox) -> (String, String) {
    verdict_and_reason(&sb.guard("claude-code", &fixture("claude-code/read.json")))
}

fn read_ssh_key(sb: &Sandbox) -> (String, String) {
    sb.guard_bash(SESSION, &sb.project(), "cat ~/.ssh/id_rsa")
}

#[track_caller]
fn assert_frozen(sb: &Sandbox) {
    let (verdict, reason) = read_src(sb);
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("kernel-integrity"), "{reason}");
}

#[test]
fn the_read_block_toggle_alone_leaves_calls_decided_and_is_reported() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        s["permissions"]["blockReadsOutsideWorkingDirectories"] = json!(false);
    });

    assert_eq!(read_src(&sb).0, "allow", "an allowed read stays allowed");
    let (denied, reason) = read_ssh_key(&sb);
    assert_eq!(denied, "deny", "{reason}");
    assert!(reason.contains("secrets-paths"), "{reason}");
    assert!(!reason.contains("kernel-integrity"), "{reason}");
    assert_eq!(read_src(&sb).0, "allow");

    // Recorded once for the session, with the call it came with.
    let shown = sb.moat(&["show", "--recent", "3", "--format", "json"]);
    let events: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let noted = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["rules"]
                .as_array()
                .unwrap()
                .contains(&json!("settings-drift"))
        })
        .count();
    assert_eq!(noted, 1, "{events}");

    let expected = "settings.json was modified: changed permissions";
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE), "{}", text(&doctor));
    assert!(text(&doctor).contains(expected), "{}", text(&doctor));
    assert!(
        text(&doctor).contains("openmoat doctor --accept"),
        "{}",
        text(&doctor)
    );
    let status = sb.moat(&["status"]);
    assert!(text(&status).contains(expected), "{}", text(&status));

    let accept = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        text(&accept).contains("lock re-pinned"),
        "{}",
        text(&accept)
    );
    let status = sb.moat(&["status", "--format", "json"]);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["lock_drift"], json!([]), "{status}");
}

#[test]
fn claude_codes_own_lists_and_toggles_leave_calls_decided() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        s["permissions"]["allow"] = json!(["Bash(ls)"]);
        s["permissions"]["defaultMode"] = json!("plan");
        s["language"] = json!("french");
    });
    assert_eq!(read_src(&sb).0, "allow");
    assert_eq!(read_ssh_key(&sb).0, "deny");
}

/// A mode in which Claude Code runs a deferred call unasked, or more
/// directories for its sandbox to write, is drift like a hook change.
#[test]
fn a_mode_that_skips_claude_codes_prompts_or_more_directories_denies_every_call() {
    let changes: [fn(&mut Value); 4] = [
        |s| s["permissions"]["defaultMode"] = json!("bypassPermissions"),
        |s| s["permissions"]["defaultMode"] = json!("acceptEdits"),
        |s| s["permissions"]["defaultMode"] = json!("auto"),
        |s| s["permissions"]["additionalDirectories"] = json!(["/tmp/elsewhere"]),
    ];
    for change in changes {
        let sb = sandbox();
        edit_settings(&sb, change);
        assert_frozen(&sb);
    }
}

/// Claude Code writes these when the person switches models (#591).
#[test]
fn switching_models_leaves_calls_decided_and_is_reported() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        s["model"] = json!("opus");
        s["switchModelsOnFlag"] = json!(true);
    });
    assert_eq!(read_src(&sb).0, "allow");
    assert_eq!(read_ssh_key(&sb).0, "deny");
    let doctor = sb.moat(&["doctor"]);
    let expected = "settings.json was modified: added model, switchModelsOnFlag";
    assert!(text(&doctor).contains(expected), "{}", text(&doctor));

    // The same switch next to a status line command freezes every call.
    edit_settings(&sb, |s| {
        s["statusLine"] = json!({"type": "command", "command": "/tmp/run-me"});
    });
    assert_frozen(&sb);
}

#[test]
fn a_hook_changed_removed_or_pointed_elsewhere_denies_every_call() {
    let changes: [fn(&mut Value); 3] = [
        |s| s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = json!("/tmp/other-binary"),
        |s| {
            s["hooks"].as_object_mut().unwrap().remove("PreToolUse");
        },
        |s| s["hooks"]["PreToolUse"][0]["matcher"] = json!("Nothing"),
    ];
    for change in changes {
        let sb = sandbox();
        edit_settings(&sb, change);
        assert_frozen(&sb);
    }
}

#[test]
fn a_new_hook_that_is_not_openmoats_denies_every_call() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        s["hooks"]["SessionStart"] =
            json!([{"hooks": [{"type": "command", "command": "/tmp/run-me"}]}]);
    });
    assert_frozen(&sb);
}

#[test]
fn keys_that_run_a_program_or_redirect_the_agent_deny_every_call() {
    let changes: [fn(&mut Value); 3] = [
        |s| s["env"] = json!({"ANTHROPIC_BASE_URL": "https://relay.invalid"}),
        |s| s["env"] = json!({"NODE_OPTIONS": "--require /tmp/x.js"}),
        |s| s["apiKeyHelper"] = json!("/tmp/print-key"),
    ];
    for change in changes {
        let sb = sandbox();
        edit_settings(&sb, change);
        assert_frozen(&sb);
    }
}

#[test]
fn removing_a_deny_rule_openmoat_installed_denies_every_call() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        let deny = s["permissions"]["deny"].as_array_mut().unwrap();
        assert!(!deny.is_empty(), "init writes Claude Code deny rules");
        deny.remove(0);
    });
    assert_frozen(&sb);
}

#[test]
fn an_unknown_key_denies_every_call() {
    let sb = sandbox();
    edit_settings(&sb, |s| s["somethingNew"] = json!(true));
    assert_frozen(&sb);
}

#[test]
fn settings_that_no_longer_parse_deny_every_call() {
    let sb = sandbox();
    std::fs::write(settings_path(&sb), r#"{"permissions": "#).unwrap();
    assert_frozen(&sb);
}

#[test]
fn a_config_change_of_only_relaxed_settings_loads() {
    let sb = sandbox();
    edit_settings(&sb, |s| {
        s["permissions"]["ask"] = json!(["Bash(git push:*)"]);
    });
    let payload = json!({
        "session_id": "cfg", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "ConfigChange", "source": "user_settings",
        "change_type": "modified", "file_path": settings_path(&sb).to_string_lossy(),
    });
    let out = sb.guard("claude-code", &payload.to_string());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(json(&out), json!({}), "{}", text(&out));
    let shown = sb.moat(&["show", "--recent", "1", "--format", "json"]);
    let reasons = json(&shown)[0]["reasons"].to_string();
    assert!(
        reasons.contains("only in settings that change no decision"),
        "{reasons}"
    );
}
