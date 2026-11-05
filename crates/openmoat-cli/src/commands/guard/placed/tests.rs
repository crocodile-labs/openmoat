use std::path::{Path, PathBuf};

use openmoat_core::Action;
use openmoat_hosts::{HookRequest, Host};

use super::in_session;
use crate::context::path_string;

fn shell(host: Host, cwd: &Path, command: &str) -> HookRequest {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "cwd": path_string(cwd),
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    host.parse_request(&payload.to_string()).unwrap()
}

fn placed(host: Host, session: &Path, tool: &Path, command: &str) -> HookRequest {
    let session = session.to_path_buf();
    let fixed = move || -> std::io::Result<PathBuf> { Ok(session.clone()) };
    in_session(host, shell(host, tool, command), &fixed).unwrap()
}

/// Codex's `cwd` is the model's `workdir`: outside the session's project the
/// call is decided from the session's directory, as running where it runs.
#[test]
fn a_codex_workdir_outside_the_project_never_becomes_the_project() {
    let dir = tempfile::tempdir().unwrap();
    let proj = dir.path().join("proj");
    let agents = dir.path().join("Library/LaunchAgents");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::create_dir_all(proj.join("sub")).unwrap();
    std::fs::create_dir_all(&agents).unwrap();

    let inside = placed(Host::Codex, &proj, &proj.join("sub"), "make");
    assert_eq!(
        inside.cwd.as_deref(),
        Some(path_string(&proj.join("sub")).as_str())
    );
    assert_eq!(
        inside.action,
        Some(Action::Shell {
            command: "make".to_owned()
        })
    );

    let outside = placed(Host::Codex, &proj, &agents, "printf x > evil.plist");
    assert_eq!(outside.cwd.as_deref(), Some(path_string(&proj).as_str()));
    let expected = format!("cd '{}' && printf x > evil.plist", path_string(&agents));
    assert_eq!(outside.action, Some(Action::Shell { command: expected }));

    // Hosts whose payload `cwd` is the session's are left as they are.
    let claude = placed(Host::ClaudeCode, &proj, &agents, "ls");
    assert_eq!(claude.cwd.as_deref(), Some(path_string(&agents).as_str()));
}

/// A session started outside any project (the home directory) keeps a
/// workdir inside a git work tree, and only there.
#[test]
fn a_session_outside_any_project_keeps_only_a_git_work_tree() {
    let home = crate::home::user_home().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let plain = dir.path().join("plain");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(&plain).unwrap();
    let kept = placed(Host::Codex, &home, &repo, "ls");
    assert_eq!(kept.cwd.as_deref(), Some(path_string(&repo).as_str()));
    let moved = placed(Host::Codex, &home, &plain, "ls");
    assert_eq!(moved.cwd.as_deref(), Some(path_string(&home).as_str()));
}
