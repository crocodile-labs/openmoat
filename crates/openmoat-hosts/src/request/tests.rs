use openmoat_core::Action;

use super::{EVERY_WORKSPACE_DIRECTORY, is_inside};
use crate::{HookEvent, HookRequest, Host};

fn request(cwd: &str, action: Action) -> HookRequest {
    HookRequest {
        host: Host::Codex,
        session_id: "s".to_owned(),
        call_id: None,
        cwd: Some(cwd.to_owned()),
        tool: "Bash".to_owned(),
        action: Some(action),
        content: None,
        edits: Vec::new(),
        mcp_arguments: None,
        sandboxed: false,
        event: HookEvent::PreToolUse,
    }
}

fn shell(command: &str) -> Action {
    Action::Shell {
        command: command.to_owned(),
    }
}

/// A call run in a model-chosen directory is decided from the session's,
/// as running there: a `cd` before a command, relative paths joined to it.
#[test]
fn a_tool_directory_runs_the_call_but_never_decides_the_project() {
    let moved = request("/h/Library/LaunchAgents", shell("printf x > evil.plist"))
        .from_session_dir("/h/proj");
    assert_eq!(moved.cwd.as_deref(), Some("/h/proj"));
    assert_eq!(
        moved.action,
        Some(shell(
            "cd '/h/Library/LaunchAgents' && printf x > evil.plist"
        ))
    );
    let quoted = request("/h/it's", shell("ls")).from_session_dir("/h/proj");
    assert_eq!(quoted.action, Some(shell(r"cd '/h/it'\''s' && ls")));
    let read = request(
        "/h/other",
        Action::ReadFiles {
            paths: vec!["n.txt".to_owned(), "/abs".to_owned(), "~/x".to_owned()],
        },
    )
    .from_session_dir("/h/proj");
    assert_eq!(
        read.action,
        Some(Action::ReadFiles {
            paths: vec![
                "/h/other/n.txt".to_owned(),
                "/abs".to_owned(),
                "~/x".to_owned()
            ]
        })
    );
    let held =
        request("/h/other", Action::unchecked(shell("ls"), "why")).from_session_dir("/h/proj");
    assert_eq!(
        held.action,
        Some(Action::unchecked(shell("cd '/h/other' && ls"), "why"))
    );
}

/// The session's own directory changes nothing.
#[test]
fn the_session_directory_is_left_as_it_is() {
    for cwd in ["/h/proj", "/h/proj/"] {
        let same = request(cwd, shell("ls")).from_session_dir("/h/proj");
        assert_eq!(same.action, Some(shell("ls")), "{cwd}");
        assert_eq!(same.cwd.as_deref(), Some(cwd));
    }
}

#[test]
fn inside_is_by_whole_segments_and_never_through_dot_dot() {
    assert!(is_inside("/h/proj", "/h/proj"));
    assert!(is_inside("/h/proj/src", "/h/proj/"));
    assert!(is_inside("C:\\p\\src", "C:/p"));
    assert!(is_inside("/anything", "/"));
    assert!(!is_inside("/h/project", "/h/proj"));
    assert!(!is_inside("/h/proj/../.ssh", "/h/proj"));
    assert!(!is_inside("/h", "/h/proj"));
}

/// A workspace-wide search reads the directories the settings add, or the
/// working directory alone, instead of needing review.
#[test]
fn a_workspace_search_reads_the_directories_the_settings_add() {
    let search = || {
        request(
            "/p",
            Action::unchecked(
                Action::FsRead {
                    path: "/p".to_owned(),
                },
                EVERY_WORKSPACE_DIRECTORY,
            ),
        )
    };
    assert!(search().searches_workspace());
    let alone = search().with_workspace_dirs(&[]);
    assert_eq!(
        alone.action,
        Some(Action::FsRead {
            path: "/p".to_owned()
        })
    );
    assert!(!alone.searches_workspace());
    let extra = search().with_workspace_dirs(&["~/.ssh".to_owned(), "lib".to_owned()]);
    assert_eq!(
        extra.action,
        Some(Action::ReadFiles {
            paths: vec!["/p".to_owned(), "~/.ssh".to_owned(), "/p/lib".to_owned()]
        })
    );
    // Another mark stays.
    let other = request("/p", Action::unchecked(shell("ls"), "typed input"));
    assert!(!other.searches_workspace());
    assert_eq!(other.clone().with_workspace_dirs(&[]).action, other.action);
}
