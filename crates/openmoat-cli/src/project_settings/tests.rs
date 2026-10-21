use serde_json::json;

use super::*;

fn warnings(cwd: &Path, user_home: &Path) -> Vec<String> {
    super::warnings(cwd, user_home, Host::ClaudeCode)
}

/// A repository's Copilot settings that turn hooks off, and each hook file in
/// its `.github/hooks`, are named with the agent that loads them.
#[test]
fn copilot_repository_settings_and_hook_files_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".github/copilot")).unwrap();
    fs::create_dir_all(project.join(".github/hooks")).unwrap();
    let copilot = || super::warnings(&project, &user_home, Host::CopilotCli);
    assert!(copilot().is_empty());
    fs::write(
        project.join(".github/copilot/settings.json"),
        r#"{"model": "gpt-5"}"#,
    )
    .unwrap();
    fs::write(project.join(".github/hooks/notes.txt"), "not a hook").unwrap();
    assert!(
        copilot().is_empty(),
        "a model choice and other files are left alone"
    );
    fs::write(
        project.join(".github/copilot/settings.local.json"),
        r#"{"disableAllHooks": true}"#,
    )
    .unwrap();
    fs::write(project.join(".github/hooks/audit.json"), "{}").unwrap();
    let rows = copilot();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].contains("`disableAllHooks`"), "{rows:?}");
    assert!(rows[1].contains("audit.json: adds hooks"), "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r.contains("A GitHub Copilot CLI session")),
        "{rows:?}"
    );
    assert!(
        warnings(&project, &user_home).is_empty(),
        "not Claude Code's"
    );
}

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
        "extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "o/r"}}},
        "enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["db"],
    }));
    assert_eq!(all.len(), 15, "{all:?}");
    assert!(all[0].contains("OpenMoat's included"), "{all:?}");
    assert!(
        all.iter()
            .any(|f| f.contains("`enabledMcpjsonServers` starts MCP servers")),
        "{all:?}"
    );
}

#[test]
fn leaves_permissions_and_empty_or_switched_off_values_alone() {
    assert!(
        found(&json!({
            "permissions": {"allow": ["Bash"], "defaultMode": "acceptEdits"},
            "disableAllHooks": false, "hooks": {}, "env": {}, "apiKeyHelper": "",
            "statusLine": null, "enabledPlugins": {"p@m": false},
            "sandbox": {"enabled": true}, "model": "opus",
            "enableAllProjectMcpServers": false, "enabledMcpjsonServers": [],
            "extraKnownMarketplaces": {}, "disabledMcpjsonServers": ["db"],
        }))
        .is_empty()
    );
}

/// A file that passes the check but is rewritten before the decision is
/// reported, whatever it holds by then; one left as it was passes.
#[test]
fn a_file_rewritten_during_the_check_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    fs::write(&path, r#"{"model": "opus"}"#).unwrap();
    assert_eq!(check_unchanged(&path), None);
    let swapped = check_between(&path, || {
        fs::write(&path, r#"{"disableAllHooks": true}"#).unwrap();
    });
    assert!(swapped.unwrap().contains("changed while"));
    fs::write(&path, "{}").unwrap();
    let touched = check_between(&path, || fs::write(&path, "{ }").unwrap());
    assert!(
        touched.unwrap().contains("changed while"),
        "bytes, not meaning"
    );
    let gone = dir.path().join("gone.json");
    let created = check_between(&gone, || fs::write(&gone, "{}").unwrap());
    assert!(created.unwrap().contains("changed while"), "appeared");
    fs::remove_file(&gone).unwrap();
    assert_eq!(check_unchanged(&gone), None);
    fs::write(&path, r#"{"hooks": {"Stop": [{}]}}"#).unwrap();
    assert!(
        check_between(&path, || panic!("not read again"))
            .unwrap()
            .contains("`hooks`")
    );
}

#[test]
fn reading_tells_absent_from_broken() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_bytes(&dir.path().join("none.json")).unwrap().is_none());
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
