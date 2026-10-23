use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use crate::{HookEvent, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/pi/fixtures");

fn fixture(name: &str) -> HookRequest {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::Pi.parse_request(&text).unwrap()
}

/// A payload for `tool` with `input` in `/p`, with `extra` fields over it.
fn call(tool: &str, input: Value, extra: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "hook_event_name": "tool_call",
        "toolName": tool,
        "toolCallId": "call-1",
        "sessionId": "sess-1",
        "cwd": "/p",
        "hasUI": true,
        "platform": "darwin",
    });
    payload["input"] = input;
    if let (Value::Object(base), Value::Object(extra)) = (&mut payload, extra) {
        base.extend(extra);
    }
    Host::Pi.parse_request(&payload.to_string())
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

#[test]
fn bash_is_a_shell_command_in_the_working_directory() {
    let bash = fixture("bash");
    assert_eq!(bash.session_id, "0199f3a2-7c1e-7b2a-9d4e-1f2a3b4c5d6e");
    assert_eq!(bash.call_id.as_deref(), Some("toolu_bash_1"));
    assert_eq!(bash.cwd.as_deref(), Some("/p"));
    assert_eq!(bash.event, HookEvent::PreToolUse);
    assert_eq!(
        bash.action,
        Some(Action::Shell {
            command: "cargo test --workspace".into()
        })
    );
    assert!(matches!(
        fixture("powershell").action,
        Some(Action::ForeignShell { shell, command }) if shell == "PowerShell" && command == "Get-ChildItem"
    ));
}

#[test]
fn file_tools_read_and_write_the_path_they_name() {
    assert_eq!(fixture("read").action, read("src/main.rs"));
    assert_eq!(fixture("read-secret").action, read("~/.ssh/id_ed25519"));
    let write = fixture("write");
    assert_eq!(
        write.action,
        Some(Action::FsWrite {
            path: "/p/notes.txt".into()
        })
    );
    assert_eq!(write.content.as_deref(), Some("hello\n"));
    let edit = fixture("edit");
    assert_eq!(
        edit.action,
        Some(Action::FsWrite {
            path: "src/lib.rs".into()
        })
    );
    assert_eq!(edit.content, None);
    assert_eq!(
        fixture("edit-extension").action,
        Some(Action::FsWrite {
            path: "~/.pi/agent/extensions/openmoat.js".into()
        })
    );
    // A call another tool made is checked like any other.
    assert_eq!(fixture("codemode-nested").action, read("README.md"));
}

#[test]
fn search_tools_read_their_path_or_the_working_directory() {
    assert_eq!(fixture("grep").action, read("/p"));
    assert_eq!(fixture("ls").action, read("~/.aws"));
    assert_eq!(fixture("find").action, read("crates"));
    assert_eq!(action("ls", json!({})), read("/p"));
    assert_eq!(
        action("find", json!({"pattern": "/etc/**/*.conf"})),
        Some(Action::ReadFiles {
            paths: vec!["/p".into(), "/etc".into()]
        })
    );
    let no_cwd = call("grep", json!({"pattern": "x"}), json!({"cwd": ""}));
    assert!(matches!(no_cwd, Err(HostError::MalformedArguments { .. })));
}

/// pi's `read` falls back to a screenshot's ` AM.` with a narrow no-break space
/// and to `’` for `'`; the hook reads each spelling.
#[test]
fn a_read_names_every_spelling_pi_may_open() {
    assert_eq!(
        action("read", json!({"path": "~/Shot 9.41.02 pm.png"})),
        Some(Action::ReadFiles {
            paths: vec!["~/Shot 9.41.02 pm.png".into(), "~/Shot 9.41.02\u{202F}pm.png".into()],
        })
    );
    assert_eq!(
        action("read", json!({"path": "~/d'x/k"})),
        Some(Action::ReadFiles {
            paths: vec!["~/d'x/k".into(), "~/d\u{2019}x/k".into()],
        })
    );
    // a plain name, and a space before something else, stay one read
    assert_eq!(action("read", json!({"path": "~/.ssh/id_rsa"})), read("~/.ssh/id_rsa"));
    assert_eq!(action("read", json!({"path": "~/a am/b é.x"})), read("~/a am/b é.x"));
}

/// pi drops a leading `@`, turns Unicode spaces into spaces, reads `file:`
/// URLs as paths and, on Windows, Git Bash drive paths as drives.
#[test]
fn paths_are_read_as_pi_resolves_them() {
    assert_eq!(
        action("read", json!({"path": "@src/a.rs"})),
        read("src/a.rs")
    );
    assert_eq!(
        action("read", json!({"path": "~/My\u{202F}Notes.txt"})),
        read("~/My Notes.txt")
    );
    assert_eq!(
        action("read", json!({"path": "file:///Users/me/.aws/credentials"})),
        read("/Users/me/.aws/credentials")
    );
    let windows = |path: &str| {
        call("read", json!({"path": path}), json!({"platform": "win32"}))
            .unwrap()
            .action
    };
    assert_eq!(
        windows("/c/Users/me/.ssh/id_rsa"),
        read("C:/Users/me/.ssh/id_rsa")
    );
    assert_eq!(windows("/mnt/d/x"), read("D:/x"));
    assert_eq!(windows("/cygdrive/c"), read("C:/"));
    assert_eq!(windows("file:///C:/Users/me/x"), read("C:/Users/me/x"));
    assert_eq!(windows("/tmp/x"), read("/tmp/x"));
    // Elsewhere `/c/x` is a path of its own.
    assert_eq!(action("read", json!({"path": "/c/x"})), read("/c/x"));
    let relative = call("read", json!({"path": "a.rs"}), json!({"cwd": null}));
    assert!(matches!(
        relative,
        Err(HostError::MalformedArguments { .. })
    ));
}

#[test]
fn mcp_tools_and_unknown_tools() {
    assert!(matches!(
        fixture("mcp").action,
        Some(Action::McpTool { name, reads, .. })
            if name == "mcp__files__read_file" && reads == ["/Users/me/.ssh/id_rsa"]
    ));
    assert!(matches!(
        action("read_mcp_resource", json!({"server": "docs", "uri": "file:///etc/passwd"})),
        Some(Action::McpTool { name, reads, .. })
            if name == "mcp__docs__read_resource" && reads == ["/etc/passwd"]
    ));
    assert_eq!(
        fixture("unknown-tool").action,
        Some(Action::UnknownTool {
            host: "pi".into(),
            tool: "deploy".into(),
            reads: vec![],
            writes: vec!["prod".into()],
            hosts: vec![],
            commands: vec![],
        })
    );
    // pi runs a call OpenMoat makes no decision on: an extension's tool is
    // checked for the paths, URLs and commands its input names
    let custom = action("custom_read", json!({"path": "~/.ssh/id_rsa"}));
    assert!(
        matches!(custom, Some(Action::UnknownTool { ref reads, .. }) if reads == &["~/.ssh/id_rsa"]),
        "{custom:?}"
    );
    for tool in ["codemode", "tool_search", "list_mcp_resources"] {
        assert_eq!(action(tool, json!({})), None, "{tool}");
    }
}

#[test]
fn malformed_input_is_an_error() {
    let text = std::fs::read_to_string(format!("{FIXTURES}/read-malformed.json")).unwrap();
    assert!(matches!(
        Host::Pi.parse_request(&text),
        Err(HostError::MissingField { field: "path", .. })
    ));
    for (tool, input) in [
        ("bash", json!({})),
        ("write", json!({"content": "x"})),
        ("grep", json!({"pattern": "x", "path": 3})),
        ("read", json!({"path": "file://host"})),
    ] {
        assert!(call(tool, input, json!({})).is_err(), "{tool}");
    }
    let nameless = json!({"hook_event_name": "tool_call", "toolName": ""}).to_string();
    assert!(matches!(
        Host::Pi.parse_request(&nameless),
        Err(HostError::MissingField {
            field: "toolName",
            ..
        })
    ));
}

/// Without a screen (print or JSON mode) pi cannot ask: an `ask` arrives as a
/// deny that says how to approve it, and a `defer` stays no decision.
#[test]
fn print_mode_cannot_ask() {
    let request = fixture("print-mode");
    assert_eq!(request.event, HookEvent::PreToolUseNoAsk);
    let ask = Host::Pi.answer(&request.event, &Decision::new(Verdict::Ask));
    assert_eq!(ask.verdict, Verdict::Deny);
    assert!(
        ask.reasons.concat().contains("openmoat allow --last"),
        "{ask:?}"
    );
    let defer = Host::Pi.decided(&request.event, Decision::new(Verdict::Defer));
    assert_eq!(defer.verdict, Verdict::Defer);
    let ui = Host::Pi.answer(&HookEvent::PreToolUse, &Decision::new(Verdict::Ask));
    assert_eq!(ui.verdict, Verdict::Ask);
}

#[test]
fn render_prints_nothing_for_defer_and_the_decision_otherwise() {
    let event = HookEvent::PreToolUse;
    assert_eq!(
        Host::Pi.render_response(&event, &Decision::new(Verdict::Defer)),
        ""
    );
    for verdict in [Verdict::Allow, Verdict::Ask, Verdict::Deny] {
        let text = Host::Pi.render_response(&event, &Decision::new(verdict));
        let reply: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(reply["decision"], verdict.as_str());
        assert!(reply["reason"].as_str().unwrap().starts_with("moat: "));
    }
}

#[test]
fn other_events_are_not_pis() {
    let other = json!({"hook_event_name": "tool_result", "toolName": "bash"}).to_string();
    assert!(matches!(
        Host::Pi.parse_request(&other),
        Err(HostError::WrongEvent(event)) if event == "tool_result"
    ));
}
