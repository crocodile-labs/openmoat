//! OpenCode 2's payloads (`fixtures/v2-*.json`, built from the 2.2.0 source):
//! its tool names and arguments, `~` expanded as OpenCode 2 expands it, and
//! asks that reach the person.

use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use super::fixture;
use crate::{HookEvent, HookRequest, Host, HostError};

/// An `execute.before` payload for `tool` with `input` in `/p`.
fn call(tool: &str, input: Value, extra: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "hook_event_name": "execute.before",
        "tool": tool, "sessionID": "ses_2", "agent": "build", "messageID": "msg_1",
        "callID": "call-2", "directory": "/p", "worktree": "/p",
        "mcpServers": [], "platform": "darwin",
    });
    payload["input"] = input;
    if let (Value::Object(base), Value::Object(extra)) = (&mut payload, extra) {
        base.extend(extra);
    }
    Host::OpenCode.parse_request(&payload.to_string())
}

fn action(tool: &str, input: Value) -> Option<Action> {
    call(tool, input, json!({})).unwrap().action
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "compared with `HookRequest::action`, which is an `Option`"
)]
fn read(path: &str) -> Option<Action> {
    Some(Action::FsRead {
        path: path.to_owned(),
    })
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "compared with `HookRequest::action`, which is an `Option`"
)]
fn write(path: &str) -> Option<Action> {
    Some(Action::FsWrite {
        path: path.to_owned(),
    })
}

#[test]
fn shell_is_a_shell_command_in_its_workdir_and_asks_can_be_asked() {
    let shell = fixture("v2-shell");
    assert_eq!(shell.event, HookEvent::PreToolUse);
    assert_eq!(shell.session_id, "ses_7c41d2a09ffeQrStUvWxYzAbCd");
    assert_eq!(shell.call_id.as_deref(), Some("call_v2_shell"));
    assert_eq!(shell.cwd.as_deref(), Some("/p"));
    assert!(matches!(
        fixture("v2-shell-windows").action,
        Some(Action::ForeignShell { command, .. }) if command == "Get-ChildItem"
    ));
    if cfg!(windows) {
        return;
    }
    assert_eq!(
        shell.action,
        Some(Action::Shell {
            command: "cargo test --workspace".into()
        })
    );
    // OpenCode 2 expands a `~` in `workdir`, so it is left unquoted.
    assert_eq!(
        fixture("v2-shell-workdir").action,
        Some(Action::Shell {
            command: "cd ~/'other' && cat .env".into()
        })
    );
    assert_eq!(
        action("shell", json!({"command": "ls", "workdir": "~"})),
        Some(Action::Shell {
            command: "cd ~ && ls".into()
        })
    );
    assert_eq!(
        action("shell", json!({"command": "ls", "workdir": "it's"})),
        Some(Action::Shell {
            command: r"cd 'it'\''s' && ls".into()
        })
    );
}

#[test]
fn file_tools_take_path_and_expand_a_leading_tilde() {
    assert_eq!(fixture("v2-read").action, read("/p/src/main.rs"));
    assert_eq!(fixture("v2-read-home").action, read("~/.ssh/id_ed25519"));
    assert_eq!(action("read", json!({"path": "~"})), read("~"));
    // Only a leading `~` alone or before a separator is the home directory.
    assert_eq!(action("read", json!({"path": "~x/y"})), read("/p/~x/y"));
    let written = fixture("v2-write");
    assert_eq!(written.action, write("/p/notes.txt"));
    assert_eq!(written.content.as_deref(), Some("hello\n"));
    assert_eq!(fixture("v2-edit").action, write("/p/src/lib.rs"));
    assert_eq!(
        fixture("v2-patch").action,
        Some(Action::Patch {
            writes: vec!["/p/src/a.rs".into(), "/p/docs/b.md".into()]
        })
    );
    assert_eq!(
        fixture("v2-worktree-remove").action,
        write("/Users/me/.local/share/opencode/worktree/p/feature")
    );
    // On Windows `~\` is the home directory too.
    let windows = call(
        "read",
        json!({"path": r"~\.ssh\id_rsa"}),
        json!({"platform": "win32", "directory": "C:/p"}),
    )
    .unwrap();
    assert_eq!(windows.action, read(r"~/.ssh\id_rsa"));
}

#[test]
fn search_web_and_mcp_tools_are_mapped() {
    // `path: "undefined"` is no path in OpenCode 2's `glob`.
    assert!(matches!(
        fixture("v2-glob").action,
        Some(Action::FsRead { path }) if path == "/p"
    ));
    assert_eq!(fixture("v2-grep").action, read("/p/src"));
    assert_eq!(
        fixture("v2-webfetch").action,
        Some(Action::Fetch {
            url: "https://docs.rs/serde".into()
        })
    );
    assert_eq!(
        fixture("v2-websearch").action,
        Some(Action::WebSearch {
            query: "serde json flatten".into()
        })
    );
    assert!(matches!(
        fixture("v2-mcp").action,
        Some(Action::McpTool { name, .. }) if name == "mcp__github__create_issue"
    ));
    assert!(matches!(
        fixture("v2-read_mcp_resource").action,
        Some(Action::McpTool { reads, .. }) if reads == vec!["/Users/me/.aws/credentials".to_owned()]
    ));
}

#[test]
fn tools_that_touch_nothing_are_ungoverned_and_others_are_checked() {
    assert_eq!(fixture("v2-subagent").action, None);
    for tool in [
        "todowrite",
        "question",
        "skill",
        "list_mcp_resources",
        "execute",
        "opencode_session_rename",
        "opencode_worktree_list",
        "opencode_models",
    ] {
        assert_eq!(action(tool, json!({})), None, "{tool}");
    }
    // OpenCode 1's names are other tools in OpenCode 2, checked by their arguments.
    let Some(Action::McpTool { name, reads, .. }) =
        action("bash", json!({"command": "cat ~/.ssh/id_rsa", "path": "/Users/me/.ssh/id_rsa"}))
    else {
        panic!("not checked");
    };
    assert_eq!(name, "bash");
    assert!(reads.contains(&"/Users/me/.ssh/id_rsa".to_owned()), "{reads:?}");
    // A tool whose name says it moves something writes what it names.
    assert!(matches!(
        action("opencode_session_move", json!({"directory": "/Users/me/.ssh"})),
        Some(Action::McpTool { writes, .. }) if writes.contains(&"/Users/me/.ssh".to_owned())
    ));
}

#[test]
fn malformed_payloads_are_errors() {
    let text = std::fs::read_to_string(format!("{}/v2-read-malformed.json", super::FIXTURES)).unwrap();
    assert!(matches!(
        Host::OpenCode.parse_request(&text),
        Err(HostError::MissingField { field: "path", .. })
    ));
    assert!(matches!(
        call("shell", json!({}), json!({})),
        Err(HostError::MissingField { field: "command", .. })
    ));
    assert!(matches!(
        call("shell", json!({"command": "ls", "workdir": 3}), json!({})),
        Err(HostError::MalformedArguments { .. })
    ));
    assert!(matches!(
        call("", json!({}), json!({})),
        Err(HostError::MissingField { field: "tool", .. })
    ));
    let after = json!({"hook_event_name": "execute.after", "tool": "shell", "input": {}});
    assert!(matches!(
        Host::OpenCode.parse_request(&after.to_string()),
        Err(HostError::WrongEvent(event)) if event == "execute.after"
    ));
    // A payload that cannot be parsed is still answered as OpenCode 2's.
    assert_eq!(
        Host::OpenCode.event_of(r#"{"hook_event_name": "execute.before", "tool": 1}"#),
        HookEvent::PreToolUse
    );
    assert_eq!(
        Host::OpenCode.event_of(r#"{"hook_event_name": "tool.execute.before"}"#),
        HookEvent::PreToolUseNoAsk
    );
}

/// OpenCode 2 can ask: the `ask` reaches the plugin as an ask with OpenMoat's
/// reason, which it puts to the person through OpenCode's permission prompt.
#[test]
fn an_ask_stays_an_ask() {
    let event = fixture("v2-read").event;
    let mut ask = Decision::new(Verdict::Ask);
    ask.rules.push("runs-later".to_owned());
    let answered = Host::OpenCode.answer(&event, &ask);
    assert_eq!(answered.verdict, Verdict::Ask);
    let reply: Value =
        serde_json::from_str(&Host::OpenCode.render_response(&event, &answered)).unwrap();
    assert_eq!(reply["decision"], "ask");
    assert!(!reply["reason"].as_str().unwrap().contains("allow --last"), "{reply}");
}
