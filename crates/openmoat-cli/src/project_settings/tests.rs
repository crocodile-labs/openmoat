use serde_json::json;

use super::*;

fn found(value: &Value) -> Vec<String> {
    findings(value.as_object().unwrap())
}

#[test]
fn names_each_key_that_turns_hooks_off_or_runs_a_program() {
    let all = found(&json!({
        "disableAllHooks": true, "hooks": {"Stop": []}, "env": {"A": "b"},
        "apiKeyHelper": "k", "awsAuthRefresh": "r", "awsCredentialExport": "e",
        "otelHeadersHelper": "h", "statusLine": {"command": "s"},
        "subagentStatusLine": {"command": "s"}, "fileSuggestion": {"command": "f"},
        "enabledPlugins": {"p@m": true}, "sandbox": {"enabled": false},
    }));
    assert_eq!(all.len(), 12, "{all:?}");
    assert!(all[0].contains("OpenMoat's included"), "{all:?}");
}

#[test]
fn leaves_permissions_and_empty_or_switched_off_values_alone() {
    assert!(
        found(&json!({
            "permissions": {"allow": ["Bash"], "defaultMode": "acceptEdits"},
            "disableAllHooks": false, "hooks": {}, "env": {}, "apiKeyHelper": "",
            "statusLine": null, "enabledPlugins": {"p@m": false},
            "sandbox": {"enabled": true}, "model": "opus",
        }))
        .is_empty()
    );
}

#[test]
fn reading_tells_absent_from_broken() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read(&dir.path().join("none.json")).unwrap().is_none());
    assert_eq!(check(&dir.path().join("none.json")), None);
    let path = dir.path().join("settings.json");
    fs::write(&path, "// comment\n{}").unwrap();
    assert!(check(&path).unwrap().starts_with("cannot be checked"));
    fs::write(&path, " ".repeat(usize::try_from(MAX_BYTES).unwrap() + 1)).unwrap();
    assert!(check(&path).unwrap().contains("larger than"));
    fs::write(&path, r#"{"env": {"HTTPS_PROXY": "http://x"}}"#).unwrap();
    assert!(check(&path).unwrap().contains("`env`"));
}

#[test]
fn warns_for_the_session_directory_and_its_project_root_not_the_home() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    let sub = project.join("sub");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".claude")).unwrap();
    fs::create_dir_all(sub.join(".claude")).unwrap();
    fs::create_dir_all(user_home.join(".claude")).unwrap();
    fs::write(
        user_home.join(".claude/settings.json"),
        r#"{"hooks": {"Stop": [{}]}}"#,
    )
    .unwrap();
    assert!(warnings(&sub, &user_home).is_empty());
    assert!(warnings(&user_home, &user_home).is_empty(), "user settings");

    fs::write(
        project.join(".claude/settings.json"),
        r#"{"disableAllHooks": true}"#,
    )
    .unwrap();
    fs::write(sub.join(".claude/settings.local.json"), "{").unwrap();
    let rows = warnings(&sub, &user_home);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("`disableAllHooks`")),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("cannot be checked")),
        "{rows:?}"
    );
    assert!(rows[0].contains("review the file"), "{rows:?}");
}
