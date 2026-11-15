use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use super::hook_file::entry;
use super::tools::map;
use crate::wire::guard_command::{GuardCommand, sh_binary};
use crate::{HookEvent, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/qwen_code/fixtures");

fn fixture(name: &str) -> Result<HookRequest, HostError> {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::QwenCode.parse_request(&text)
}

fn call(tool: &str, input: &Value) -> Result<HookRequest, HostError> {
    let payload = json!({
        "session_id": "s-1", "cwd": "/p", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_input": input, "tool_use_id": "c-1",
    });
    Host::QwenCode.parse_request(&payload.to_string())
}

#[expect(clippy::unnecessary_wraps, reason = "compared with an `Option`")]
fn read(path: &str) -> Option<Action> {
    Some(Action::FsRead {
        path: path.to_owned(),
    })
}

#[expect(clippy::unnecessary_wraps, reason = "compared with an `Option`")]
fn write(path: &str) -> Option<Action> {
    Some(Action::FsWrite {
        path: path.to_owned(),
    })
}

#[test]
fn each_fixture_maps_to_its_action() {
    let shell = fixture("run_shell_command").unwrap();
    assert_eq!(shell.host, Host::QwenCode);
    assert_eq!(shell.call_id.as_deref(), Some("call_qwen_01"));
    assert_eq!(shell.cwd.as_deref(), Some("/p"));
    assert_eq!(shell.event, HookEvent::PreToolUse);
    if !super::tools::POWERSHELL {
        assert_eq!(
            shell.action,
            Some(Action::Shell {
                command: "cat ~/.ssh/id_rsa".into()
            })
        );
    }
    assert_eq!(
        fixture("read_file").unwrap().action,
        read("/Users/me/.aws/credentials")
    );
    assert_eq!(fixture("grep_search").unwrap().action, read("/p/src"));
    assert_eq!(
        fixture("web_fetch").unwrap().action,
        Some(Action::Fetch {
            url: "https://example.com/docs".into()
        })
    );
    let mcp = fixture("mcp").unwrap();
    assert!(
        matches!(&mcp.action, Some(Action::McpTool { .. })),
        "{:?}",
        mcp.action
    );
}

/// `write_file` leaves `content`, `edit` one replacement (ADR-048).
#[test]
fn writes_carry_what_they_leave_in_the_file() {
    let whole = fixture("write_file").unwrap();
    assert_eq!(whole.action, write("/p/notes.txt"));
    assert_eq!(whole.content.as_deref(), Some("hello\n"));
    let edit = fixture("edit").unwrap();
    assert_eq!(edit.action, write("/p/src/main.rs"));
    assert_eq!(edit.edits.len(), 1);
    assert_eq!(edit.edits[0].old, "fn old()");
    assert!(!edit.edits[0].all);
}

#[test]
fn ungoverned_and_unknown_tools() {
    let todo = fixture("todo_write").unwrap();
    assert_eq!(todo.action, None);
    // A subagent, or any tool not mapped: what its arguments name is checked.
    let agent = fixture("agent").unwrap();
    assert!(
        matches!(&agent.action, Some(Action::UnknownTool { host, tool, .. })
            if host == "qwen-code" && tool == "agent"),
        "{:?}",
        agent.action
    );
    let future = call("future_tool", &json!({"path": "~/.ssh/id_rsa"})).unwrap();
    match future.action {
        Some(Action::UnknownTool { reads, .. }) => {
            assert!(reads.iter().any(|r| r.contains(".ssh")), "{reads:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_shell_call_runs_where_its_directory_says() {
    let input = json!({"command": "ls", "is_background": false, "directory": "src/it's"});
    assert_eq!(
        map("run_shell_command", &input, Some("/p"), false).unwrap(),
        Action::Shell {
            command: r"cd 'src/it'\''s' && ls".into()
        }
    );
    assert_eq!(
        map("run_shell_command", &input, Some("/p"), true).unwrap(),
        Action::ForeignShell {
            shell: "PowerShell".into(),
            command: "ls".into()
        }
    );
}

#[test]
fn malformed_payloads_are_errors() {
    assert!(matches!(
        fixture("read_file-malformed"),
        Err(HostError::MissingField {
            field: "file_path",
            ..
        })
    ));
    assert!(matches!(
        call("", &json!({})),
        Err(HostError::MissingField { .. })
    ));
    assert!(matches!(
        call("web_search", &json!({"q": "x"})),
        Err(HostError::MissingField { field: "query", .. })
    ));
    assert!(Host::QwenCode.parse_request("not json").is_err());
    let other = json!({"session_id": "s", "hook_event_name": "PostToolUse",
        "tool_name": "read_file", "tool_input": {"file_path": "/p/a"}});
    assert!(matches!(
        Host::QwenCode.parse_request(&other.to_string()),
        Err(HostError::WrongEvent(_))
    ));
}

/// Claude Code's reply: nothing for a `defer`, `permissionDecision` for the
/// rest, a review as `ask`.
#[test]
fn replies_are_claude_codes() {
    let render = |verdict| {
        Host::QwenCode.render_response(&HookEvent::PreToolUse, &Decision::new(verdict))
    };
    assert_eq!(render(Verdict::Defer), "");
    for (verdict, word) in [
        (Verdict::Allow, "allow"),
        (Verdict::Review, "ask"),
        (Verdict::Deny, "deny"),
    ] {
        let reply: Value = serde_json::from_str(&render(verdict)).unwrap();
        assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], word);
        assert_eq!(reply["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }
}

/// The entry is named, matches every tool, waits 600 s and quotes the binary
/// for the shell it names; its binary reads back.
#[test]
fn the_entry_runs_the_guard_in_the_shell_it_names() {
    let spec = super::HOOKS[0];
    let guard = GuardCommand::new("/Users/me/my tools/it's/openmoat");
    let posix = entry(&spec, "qwen-code", &guard, false);
    assert_eq!(posix["matcher"], "*");
    let hook = &posix["hooks"][0];
    assert_eq!((hook["name"].as_str(), hook["timeout"].as_u64()), (Some("openmoat"), Some(600)));
    assert!(hook.get("shell").is_none());
    let command = hook["command"].as_str().unwrap();
    assert_eq!(
        sh_binary(command, "qwen-code").as_deref(),
        Some("/Users/me/my tools/it's/openmoat")
    );
    let windows = entry(&spec, "qwen-code", &GuardCommand::new(r"C:\it's\openmoat.exe"), true);
    assert_eq!(windows["hooks"][0]["shell"], "powershell");
    let command = windows["hooks"][0]["command"].as_str().unwrap();
    assert!(command.starts_with("& '"), "{command}");
    assert_eq!(
        sh_binary(command, "qwen-code").as_deref(),
        Some(r"C:\it's\openmoat.exe")
    );
    assert_eq!(sh_binary(command, "gemini-cli"), None);
}
