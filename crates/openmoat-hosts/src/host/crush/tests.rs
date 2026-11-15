use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use super::tools::map;
use crate::wire::guard_command::GuardCommand;
use crate::{HookEvent, HookFile, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/crush/fixtures");

fn fixture(name: &str) -> Result<HookRequest, HostError> {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::Crush.parse_request(&text)
}

fn call(tool: &str, input: &Value) -> Result<HookRequest, HostError> {
    let payload = json!({
        "event": "PreToolUse", "hook_event_name": "PreToolUse", "session_id": "s-1",
        "cwd": "/p", "tool_name": tool, "tool_input": input, "tool_use_id": "c-1",
    });
    Host::Crush.parse_request(&payload.to_string())
}

#[test]
fn each_fixture_maps_to_its_action() {
    let shell = fixture("bash").unwrap();
    assert_eq!(shell.host, Host::Crush);
    assert_eq!(shell.call_id.as_deref(), Some("call_01"));
    assert_eq!(shell.cwd.as_deref(), Some("/p"));
    if !super::tools::FOREIGN_SHELL {
        assert_eq!(
            shell.action,
            Some(Action::Shell {
                command: "cat ~/.ssh/id_rsa".into()
            })
        );
    }
    assert_eq!(
        fixture("view").unwrap().action,
        Some(Action::FsRead {
            path: "/Users/me/.aws/credentials".into()
        })
    );
    assert_eq!(
        fixture("fetch").unwrap().action,
        Some(Action::Fetch {
            url: "https://example.com/docs".into()
        })
    );
    let mcp = fixture("mcp").unwrap();
    assert!(
        matches!(&mcp.action, Some(Action::McpTool { name, .. }) if name == "mcp_files_read_file"),
        "{:?}",
        mcp.action
    );
}

/// `write` leaves `content`; `edit` one replacement, `multiedit` each of its
/// `edits` (ADR-048).
#[test]
fn writes_carry_what_they_leave_in_the_file() {
    let whole = fixture("write").unwrap();
    assert_eq!(whole.content.as_deref(), Some("hello\n"));
    let edit = fixture("edit").unwrap();
    assert_eq!(edit.edits.len(), 1);
    assert!(edit.edits[0].all);
    let multi = fixture("multiedit").unwrap();
    assert_eq!(
        multi.action,
        Some(Action::FsWrite {
            path: "/p/src/main.go".into()
        })
    );
    assert_eq!(multi.edits.len(), 2);
}

/// A subagent's own calls fire no hook: starting one needs review, which
/// reaches Crush as a deny that says how to approve it.
#[test]
fn a_subagent_needs_review_and_crush_gets_it_as_a_deny() {
    let agent = fixture("agent").unwrap();
    assert!(
        matches!(&agent.action, Some(Action::Unchecked { .. })),
        "{:?}",
        agent.action
    );
    let mut review = Decision::new(Verdict::Review);
    review.rules.push("unchecked".into());
    let answered = Host::Crush.answer(&HookEvent::PreToolUse, &review);
    assert_eq!(answered.verdict, Verdict::Deny);
    assert!(crate::reason_line(&answered).contains("openmoat allow --last"));
}

#[test]
fn ungoverned_and_unknown_tools() {
    assert_eq!(fixture("todos").unwrap().action, None);
    let download = call(
        "download",
        &json!({"url": "https://example.com/x", "file_path": "/Users/me/.bashrc"}),
    )
    .unwrap();
    match download.action {
        Some(Action::UnknownTool { tool, hosts, .. }) => {
            assert_eq!(tool, "download");
            assert!(!hosts.is_empty(), "{hosts:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_shell_call_runs_where_its_working_dir_says() {
    let input = json!({"command": "ls", "working_dir": "/p/it's"});
    assert_eq!(
        map("bash", &input, Some("/p"), false).unwrap(),
        Action::Shell {
            command: r"cd '/p/it'\''s' && ls".into()
        }
    );
    assert!(matches!(
        map("bash", &input, Some("/p"), true).unwrap(),
        Action::ForeignShell { .. }
    ));
}

#[test]
fn malformed_payloads_are_errors() {
    assert!(matches!(
        fixture("view-malformed"),
        Err(HostError::MissingField {
            field: "file_path",
            ..
        })
    ));
    assert!(matches!(
        call("", &json!({})),
        Err(HostError::MissingField { .. })
    ));
    let other = json!({"event": "PostToolUse", "hook_event_name": "PostToolUse",
        "session_id": "s", "tool_name": "view", "tool_input": {"file_path": "/p/a"},
        "tool_response": "a"});
    assert!(matches!(
        Host::Crush.parse_request(&other.to_string()),
        Err(HostError::WrongEvent(_))
    ));
}

/// The flat entry runs for every tool, waits 600 s and quotes the binary for
/// `sh`; its binary reads back and another host's is not ours.
#[test]
fn the_entry_is_flat_and_runs_the_guard() {
    let spec = super::HOOKS[0];
    let guard = GuardCommand::new("/Users/me/my tools/it's/openmoat");
    let entry = super::hook_file::Crush.entry(&spec, "crush", &guard, false);
    assert!(entry.get("matcher").is_none(), "{entry}");
    assert!(entry.get("hooks").is_none(), "{entry}");
    assert_eq!(entry["name"], "openmoat");
    assert_eq!(entry["timeout"], 600);
    assert_eq!(
        super::hook_file::Crush.binary(&entry, "crush").as_deref(),
        Some("/Users/me/my tools/it's/openmoat")
    );
    assert!(super::hook_file::Crush.is_ours(&entry, "crush"));
    assert!(!super::hook_file::Crush.is_ours(&entry, "qwen-code"));
    assert!(!super::hook_file::Crush.is_ours(&json!({"command": "./lint.sh"}), "crush"));
}

#[test]
fn replies_are_claude_codes() {
    let render = |verdict| Host::Crush.render_response(&HookEvent::PreToolUse, &Decision::new(verdict));
    assert_eq!(render(Verdict::Defer), "");
    let deny: Value = serde_json::from_str(&render(Verdict::Deny)).unwrap();
    assert_eq!(deny["hookSpecificOutput"]["permissionDecision"], "deny");
}
