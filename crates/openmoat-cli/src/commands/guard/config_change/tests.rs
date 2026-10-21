use std::fs;

use openmoat_hosts::Host;
use serde_json::json;

use super::*;

/// A state directory whose lock pins a user settings file, and a project.
struct World {
    _dir: tempfile::TempDir,
    home: Home,
    user: PathBuf,
    project: PathBuf,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    fs::create_dir_all(home.root()).unwrap();
    // Not under `.claude`: a session that runs these tests may itself be kept
    // from writing a `.claude/settings.json`. The lock is what makes it pinned.
    let user = dir.path().join("user/claude/settings.json");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
    Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&user))
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    let project = dir.path().join("proj");
    fs::create_dir_all(project.join(".claude")).unwrap();
    fs::create_dir_all(project.join("named")).unwrap();
    World {
        _dir: dir,
        home,
        user,
        project,
    }
}

fn decide(w: &World, source: &str, path: Option<&Path>) -> Decision {
    let mut payload = json!({
        "session_id": "s", "cwd": w.project.to_string_lossy(),
        "hook_event_name": "ConfigChange", "source": source,
    });
    if let Some(path) = path {
        payload["file_path"] = path.to_string_lossy().into();
    }
    let request = Host::ClaudeCode
        .parse_request(&payload.to_string())
        .unwrap();
    decision(&w.home, &request, source, "changed").unwrap()
}

/// A file a change names: judged by its source and contents wherever it is,
/// so it is written outside `.claude` (see [`world`]).
fn project_file(w: &World, name: &str, contents: &str) -> PathBuf {
    let path = w.project.join("named").join(name);
    fs::write(&path, contents).unwrap();
    path
}

/// A file in the project's `.claude`, found from the session's directory.
fn claude_file(w: &World, name: &str, contents: &str) {
    fs::write(w.project.join(".claude").join(name), contents).unwrap();
}

fn assert_blocked(d: &Decision, what: &str) {
    assert_eq!(d.verdict, Verdict::Deny, "{what}: {d:?}");
    assert_eq!(d.rules, vec![project_settings::RULE.to_owned()], "{what}");
    let reason = d.reasons.join(" ");
    assert!(reason.contains("not loaded into this session"), "{reason}");
    assert!(reason.contains("Review the file"), "{reason}");
}

#[test]
fn each_key_that_turns_hooks_off_or_runs_code_blocks_a_project_change() {
    let w = world();
    let cases = [
        json!({"disableAllHooks": true}),
        json!({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "x"}]}]}}),
        json!({"env": {"ANTHROPIC_BASE_URL": "https://example.invalid"}}),
        json!({"apiKeyHelper": "./key.sh"}),
        json!({"awsAuthRefresh": "./refresh.sh"}),
        json!({"awsCredentialExport": "./export.sh"}),
        json!({"otelHeadersHelper": "./headers.sh"}),
        json!({"statusLine": {"type": "command", "command": "./line.sh"}}),
        json!({"subagentStatusLine": {"type": "command", "command": "./line.sh"}}),
        json!({"fileSuggestion": {"type": "command", "command": "./find.sh"}}),
        json!({"enabledPlugins": {"tool@market": true}}),
        json!({"sandbox": {"enabled": false}}),
        json!({"sandbox": {"filesystem": {"allowWrite": ["~"]}}}),
        json!({"enableAllProjectMcpServers": true}),
        json!({"enabledMcpjsonServers": ["db"]}),
        json!({"extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "o/r"}}}}),
    ];
    for (source, name) in [
        ("project_settings", "settings.json"),
        ("local_settings", "settings.local.json"),
    ] {
        for case in &cases {
            let path = project_file(&w, name, &case.to_string());
            assert_blocked(&decide(&w, source, Some(&path)), &case.to_string());
        }
    }
}

#[test]
fn ordinary_project_settings_load() {
    let w = world();
    let path = project_file(
        &w,
        "settings.json",
        &json!({
            "permissions": {"allow": ["Bash(cargo test:*)"], "deny": ["Read(.env)"]},
            "disableAllHooks": false, "hooks": {}, "env": {},
            "enabledPlugins": {"tool@market": false}, "sandbox": {"enabled": true},
            "outputStyle": "Explanatory",
        })
        .to_string(),
    );
    let d = decide(&w, "project_settings", Some(&path));
    assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
    assert_eq!(d.rules, vec![CONFIG_CHANGE_RULE.to_owned()]);
    assert!(d.reasons[0].contains("not pinned by OpenMoat"), "{d:?}");
}

#[test]
fn a_project_file_that_cannot_be_read_blocks_and_a_deleted_one_loads() {
    let w = world();
    for bad in ["{\"disableAllHooks\": ", "[]", ""] {
        let path = project_file(&w, "settings.json", bad);
        let d = decide(&w, "project_settings", Some(&path));
        assert_blocked(&d, bad);
        assert!(d.reasons[0].contains("cannot be checked"), "{d:?}");
    }
    let dir = w.project.join("named/settings.local.json");
    fs::create_dir_all(&dir).unwrap();
    assert_blocked(&decide(&w, "local_settings", Some(&dir)), "a directory");

    let gone = w.project.join("named/gone.json");
    let d = decide(&w, "project_settings", Some(&gone));
    assert_eq!(d.verdict, Verdict::Allow, "nothing to load: {d:?}");
}

#[test]
fn a_change_naming_no_file_checks_the_project_file_of_its_level() {
    let w = world();
    assert_eq!(decide(&w, "project_settings", None).verdict, Verdict::Allow);
    claude_file(&w, "settings.local.json", r#"{"disableAllHooks": true}"#);
    assert_eq!(
        decide(&w, "project_settings", None).verdict,
        Verdict::Allow,
        "the shared file is still clean"
    );
    assert_blocked(&decide(&w, "local_settings", None), "local file");
    claude_file(&w, "settings.json", r#"{"hooks": {"Stop": [{}]}}"#);
    assert_blocked(&decide(&w, "project_settings", None), "shared file");
}

#[test]
fn a_review_copy_of_a_project_file_is_judged_by_its_contents() {
    let w = world();
    let copy = project_file(
        &w,
        "settings.json.proposed-0a1b2c3d",
        r#"{"disableAllHooks": true}"#,
    );
    assert_blocked(&decide(&w, "project_settings", Some(&copy)), "copy");
    fs::write(&copy, r#"{"permissions": {"allow": ["Read"]}}"#).unwrap();
    assert_eq!(
        decide(&w, "project_settings", Some(&copy)).verdict,
        Verdict::Allow
    );
}

#[test]
fn the_pinned_user_file_is_judged_by_the_lock_not_its_contents() {
    let w = world();
    let d = decide(&w, "user_settings", Some(&w.user));
    assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
    assert!(d.reasons[0].contains("matches the policy lock"), "{d:?}");

    fs::write(&w.user, r#"{"hooks":{}}"#).unwrap();
    let d = decide(&w, "user_settings", Some(&w.user));
    assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
    assert_eq!(d.rules, vec![INTEGRITY_RULE.to_owned()]);

    let clean = project_file(&w, "settings.json", "{}");
    let d = decide(&w, "project_settings", Some(&clean));
    assert_eq!(
        d.rules,
        vec![INTEGRITY_RULE.to_owned()],
        "pinned drift blocks first"
    );
}
