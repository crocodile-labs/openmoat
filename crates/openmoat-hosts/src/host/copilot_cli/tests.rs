use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use crate::{HookEvent, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/host/copilot_cli/fixtures"
);

fn fixture(name: &str) -> HookRequest {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::CopilotCli.parse_request(&text).unwrap()
}

fn fixture_error(name: &str) -> HostError {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::CopilotCli.parse_request(&text).unwrap_err()
}

/// A payload for `tool` with `args` as an object, in `/p`.
fn call(tool: &str, args: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "sessionId": "sess-1", "timestamp": 1, "cwd": "/p", "toolName": tool,
    });
    payload["toolArgs"] = args;
    Host::CopilotCli.parse_request(&payload.to_string())
}

fn action(tool: &str, args: Value) -> Option<Action> {
    call(tool, args).unwrap().action
}

/// The action of a call that reads `path`, as `HookRequest::action` holds it.
#[expect(clippy::unnecessary_wraps, reason = "compared with an `Option`")]
fn read(path: &str) -> Option<Action> {
    Some(Action::FsRead { path: path.into() })
}

/// The action of a call that writes `path`, as `HookRequest::action` holds it.
#[expect(clippy::unnecessary_wraps, reason = "compared with an `Option`")]
fn write(path: &str) -> Option<Action> {
    Some(Action::FsWrite { path: path.into() })
}

/// Keys typed into a running shell are checked on their own and ask at
/// least: the shell joins them to what came before.
#[expect(clippy::unnecessary_wraps, reason = "compared with an `Option`")]
fn typed(input: Action) -> Option<Action> {
    Some(Action::unchecked(
        input,
        "input typed into a running shell joins what was typed before, which this call \
         does not show",
    ))
}

#[test]
fn shell_tools_are_commands_and_typed_input_asks() {
    let bash = fixture("bash");
    assert_eq!(bash.session_id, "sess-1");
    assert_eq!(bash.cwd.as_deref(), Some("/p"));
    assert_eq!(bash.event, HookEvent::PreToolUse);
    assert_eq!(
        bash.action,
        Some(Action::Shell {
            command: "cargo test --workspace".into()
        })
    );
    assert_eq!(
        fixture("write_bash").action,
        typed(Action::Shell {
            command: "cat ~/.ssh/id_rsa".into()
        })
    );
    assert!(matches!(
        fixture("powershell").action,
        Some(Action::ForeignShell { shell, command }) if shell == "PowerShell" && command == "Get-ChildItem"
    ));
    assert_eq!(
        action("write_powershell", json!({"shellId": "s", "input": "dir"})),
        typed(Action::ForeignShell {
            shell: "PowerShell".into(),
            command: "dir".into()
        })
    );
}

/// Copilot's shells outlive the call and the payload names only the
/// session's directory: a command that leaves its shell somewhere OpenMoat
/// cannot know asks, one that moves to a written-out directory or not at all
/// is a plain command.
#[test]
fn a_shell_left_in_an_unknown_directory_asks() {
    for command in ["cd \"$HOME/.ssh\"", "cd -", "eval \"$X\"", "popd"] {
        let got = action("bash", json!({"command": command}));
        assert!(
            matches!(got, Some(Action::Unchecked { .. })),
            "{command}: {got:?}"
        );
    }
    for command in ["cd ~/.ssh", "cd src && cargo test", "(cd \"$X\" && ls)"] {
        let got = action("bash", json!({"command": command}));
        assert_eq!(
            got,
            Some(Action::Shell {
                command: command.into()
            }),
            "{command}"
        );
    }
}

#[test]
fn file_tools_read_and_write_their_path() {
    assert_eq!(fixture("view").action, read("/p/src/main.rs"));
    assert_eq!(fixture("view-secret").action, read("~/.aws/credentials"));
    let create = fixture("create");
    assert_eq!(create.action, write("/p/notes.txt"));
    assert_eq!(create.content.as_deref(), Some("hello\n"));
    assert_eq!(
        fixture("create-hook-file").action,
        write("~/.copilot/hooks/openmoat.json")
    );
    let edit = fixture("edit");
    assert_eq!(edit.action, write("/p/src/main.rs"));
    assert_eq!(edit.content, None, "an edit changes part of the file");
    assert_eq!(
        action("str_replace", json!({"path": "/p/a", "old_str": "x"})),
        write("/p/a")
    );
    assert_eq!(
        action(
            "str_replace_editor",
            json!({"command": "view", "path": "/p/a"})
        ),
        read("/p/a")
    );
    assert_eq!(
        action(
            "str_replace_editor",
            json!({"command": "insert", "path": "/p/a"})
        ),
        write("/p/a")
    );
}

#[test]
fn apply_patch_writes_every_file_it_names_however_it_is_sent() {
    let want = Some(Action::Patch {
        writes: vec!["/p/src/lib.rs".into(), "/p/src/new.rs".into()],
    });
    assert_eq!(fixture("apply_patch").action, want);
    let text = "*** Begin Patch\n*** Add File: /p/x\n+y\n*** End Patch\n";
    let one = Some(Action::Patch {
        writes: vec!["/p/x".into()],
    });
    assert_eq!(action("apply_patch", json!({"input": text})), one);
    assert_eq!(action("apply_patch", json!({"patch": text})), one);
    assert!(matches!(
        call("apply_patch", json!({})),
        Err(HostError::MissingField { field: "input", .. })
    ));
}

#[test]
fn searches_read_their_paths_or_the_working_directory() {
    assert_eq!(fixture("glob").action, read("/p"));
    assert_eq!(
        fixture("grep").action,
        Some(Action::ReadFiles {
            paths: vec!["/p/src".into(), "/p/tests".into()]
        })
    );
    assert_eq!(
        action("glob", json!({"pattern": "~/.ssh/*"})),
        read("~/.ssh"),
        "an absolute glob pattern names its own directory"
    );
    assert_eq!(
        action("grep", json!({"pattern": "/etc/passwd"})),
        read("/p"),
        "a grep pattern is a regular expression, not a path"
    );
    assert_eq!(
        action("rg", json!({"pattern": "x", "paths": "/p/a"})),
        read("/p/a")
    );
    assert!(matches!(
        call("grep", json!({"pattern": "x", "paths": [1]})),
        Err(HostError::MalformedArguments { .. })
    ));
}

#[test]
fn fetch_search_and_other_tools() {
    assert_eq!(
        fixture("web_fetch").action,
        Some(Action::Fetch {
            url: "https://docs.rs/serde".into()
        })
    );
    assert_eq!(
        action("web_search", json!({"query": "serde"})),
        Some(Action::WebSearch {
            query: "serde".into()
        })
    );
    let mcp = fixture("mcp");
    assert!(
        matches!(&mcp.action, Some(Action::McpTool { name, reads, .. })
            if name == "filesystem-read_file" && reads == &["~/.ssh/id_ed25519".to_owned()]),
        "{:?}",
        mcp.action
    );
    assert_eq!(fixture("report_intent").action, None);
    assert_eq!(action("task", json!({"prompt": "x"})), None);
}

/// A call that cannot be checked is an error, so `moat guard` denies it.
#[test]
fn unreadable_payloads_are_errors() {
    assert!(matches!(
        fixture_error("malformed-args"),
        HostError::MalformedArguments { .. }
    ));
    assert!(matches!(
        call("view", json!({})),
        Err(HostError::MissingField { field: "path", .. })
    ));
    assert!(matches!(
        call("bash", json!({"command": ""})),
        Err(HostError::MissingField { .. })
    ));
    let no_tool = json!({"sessionId": "s", "toolArgs": "{}"}).to_string();
    assert!(matches!(
        Host::CopilotCli.parse_request(&no_tool),
        Err(HostError::Json(_))
    ));
    let pascal = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash"}).to_string();
    assert!(matches!(
        Host::CopilotCli.parse_request(&pascal),
        Err(HostError::WrongEvent(_))
    ));
}

#[test]
fn a_session_without_an_id_shares_the_unknown_one() {
    let payload = json!({"toolName": "view", "toolArgs": {"path": "/p/a"}}).to_string();
    let request = Host::CopilotCli.parse_request(&payload).unwrap();
    assert!(crate::is_unknown_session(&request.session_id));
    assert_eq!(request.cwd, None);
}

#[test]
fn replies_are_copilot_permission_decisions_and_defer_is_silent() {
    let render = |verdict| {
        let mut decision = Decision::new(verdict);
        decision.rules.push("secrets-paths".into());
        Host::CopilotCli.render_response(&HookEvent::PreToolUse, &decision)
    };
    let deny: Value = serde_json::from_str(&render(Verdict::Deny)).unwrap();
    assert_eq!(deny["permissionDecision"], "deny");
    assert_eq!(
        deny["permissionDecisionReason"],
        "moat: deny [secrets-paths]"
    );
    let ask: Value = serde_json::from_str(&render(Verdict::Ask)).unwrap();
    assert_eq!(ask["permissionDecision"], "ask");
    assert_eq!(render(Verdict::Defer), "");
    let ask = Decision::new(Verdict::Ask);
    assert_eq!(
        Host::CopilotCli.answer(&HookEvent::PreToolUse, &ask),
        ask,
        "an interactive Copilot session puts the question to the person"
    );
}
