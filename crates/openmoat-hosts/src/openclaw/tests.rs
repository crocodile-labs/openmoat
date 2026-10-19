use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use crate::{HookEvent, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/hosts/openclaw"
);

fn fixture(name: &str) -> HookRequest {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::OpenClaw.parse_request(&text).unwrap()
}

/// A payload for `tool` with `params`, in the workspace `/p` unless `cwd` overrides it.
fn call(tool: &str, params: Value, extra: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "hook_event_name": "before_tool_call",
        "toolName": tool,
        "sessionId": "sess-1",
        "cwd": "/p",
        "configPath": "/Users/me/.openclaw/openclaw.json",
        "platform": "darwin",
    });
    payload["params"] = params;
    if let (Value::Object(base), Value::Object(extra)) = (&mut payload, extra) {
        base.extend(extra);
    }
    Host::OpenClaw.parse_request(&payload.to_string())
}

fn action(tool: &str, params: Value) -> Option<Action> {
    call(tool, params, json!({})).unwrap().action
}

#[test]
fn exec_is_a_shell_command_with_its_env_and_workdir() {
    let exec = fixture("exec");
    assert_eq!(exec.session_id, "sess-1");
    assert_eq!(exec.call_id.as_deref(), Some("call-exec-1"));
    assert_eq!(exec.cwd.as_deref(), Some("/p"));
    assert_eq!(exec.event, HookEvent::PreToolUse);
    assert_eq!(
        exec.action,
        Some(Action::Shell {
            command: "cargo test --workspace".into()
        })
    );
    let env = fixture("exec-env");
    assert_eq!(env.cwd.as_deref(), Some("/p/app"));
    assert_eq!(
        env.action,
        Some(Action::Shell {
            command: "NODE_OPTIONS='--require /tmp/x.js' node build.js".into()
        })
    );
    let quoted = action("exec", json!({"command": "true", "env": {"A": "it's"}}));
    assert_eq!(
        quoted,
        Some(Action::Shell {
            command: r"A='it'\''s' true".into()
        })
    );
    let windows = call(
        "exec",
        json!({"command": "dir"}),
        json!({"platform": "win32"}),
    );
    assert!(matches!(
        windows.unwrap().action,
        Some(Action::ForeignShell { shell, .. }) if shell == "PowerShell"
    ));
    let code_mode = call(
        "exec",
        json!({"code": "1"}),
        json!({"toolKind": "code_mode_exec"}),
    );
    assert!(matches!(
        code_mode.unwrap().action,
        Some(Action::ForeignShell { .. })
    ));
}

#[test]
fn file_tools_read_and_write_their_paths() {
    assert_eq!(
        fixture("read").action,
        Some(Action::FsRead {
            path: "src/main.rs".into()
        })
    );
    assert_eq!(
        fixture("read-secret").action,
        Some(Action::FsRead {
            path: "/Users/me/.ssh/id_ed25519".into()
        })
    );
    let write = fixture("write");
    assert_eq!(
        write.action,
        Some(Action::FsWrite {
            path: "/p/notes.md".into()
        })
    );
    assert_eq!(write.content.as_deref(), Some("# Notes\n"));
    let edit = fixture("edit-config");
    assert_eq!(
        edit.action,
        Some(Action::FsWrite {
            path: "/Users/me/.openclaw/openclaw.json".into()
        })
    );
    assert_eq!(edit.content, None);
    // Both spellings are checked when a call carries both.
    assert_eq!(
        action(
            "read",
            json!({"path": "a.txt", "file_path": "/Users/me/.netrc"})
        ),
        Some(Action::ReadFiles {
            paths: vec!["a.txt".into(), "/Users/me/.netrc".into()]
        })
    );
    assert_eq!(
        fixture("apply_patch").action,
        Some(Action::Patch {
            writes: vec!["src/index.ts".into(), "docs/new.md".into()]
        })
    );
}

#[test]
fn network_tools_name_their_url_or_query() {
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
    assert_eq!(
        fixture("browser-navigate").action,
        Some(Action::Net {
            url: "https://example.com/".into()
        })
    );
    assert_eq!(
        action(
            "browser",
            json!({"action": "upload", "paths": ["/Users/me/.ssh/id_rsa"]})
        ),
        Some(Action::ReadFiles {
            paths: vec!["/Users/me/.ssh/id_rsa".into()]
        })
    );
    assert!(matches!(
        action("browser", json!({"action": "snapshot"})),
        Some(Action::UnknownTool { .. })
    ));
}

#[test]
fn mcp_tools_are_server_double_underscore_tool() {
    match fixture("mcp").action {
        Some(Action::McpTool { name, reads, .. }) => {
            assert_eq!(name, "mcp__filesystem__read_file");
            assert_eq!(reads, ["/Users/me/.aws/credentials"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn openclaws_own_controls_are_decided_as_its_configuration() {
    let config = "/Users/me/.openclaw/openclaw.json".to_owned();
    assert_eq!(
        fixture("plugins-disable").action,
        Some(Action::FsWrite {
            path: config.clone()
        })
    );
    assert_eq!(action("plugins", json!({"action": "list"})), None);
    assert_eq!(
        action("gateway", json!({"action": "config.get"})),
        Some(Action::FsRead { path: config })
    );
    let no_config = call(
        "plugins",
        json!({"action": "install"}),
        json!({"configPath": null}),
    );
    assert!(matches!(
        no_config,
        Err(HostError::MissingField {
            field: "configPath",
            ..
        })
    ));
}

#[test]
fn process_input_is_a_shell_openmoat_cannot_read() {
    assert!(matches!(
        fixture("process-send-keys").action,
        Some(Action::ForeignShell { .. })
    ));
    assert_eq!(
        action("process", json!({"action": "poll", "sessionId": "p"})),
        None
    );
}

#[test]
fn unknown_tools_are_unknown_and_inert_ones_ungoverned() {
    assert_eq!(
        fixture("message").action,
        Some(Action::UnknownTool {
            host: "openclaw".into(),
            tool: "message".into()
        })
    );
    assert_eq!(fixture("session_status").action, None);
}

#[test]
fn malformed_and_missing_arguments_are_errors() {
    let text = std::fs::read_to_string(format!("{FIXTURES}/read-malformed.json")).unwrap();
    assert!(matches!(
        Host::OpenClaw.parse_request(&text),
        Err(HostError::MalformedArguments { .. })
    ));
    for (tool, params) in [
        ("exec", json!({})),
        ("read", json!({})),
        ("write", json!({"content": "x"})),
        ("apply_patch", json!({})),
        ("web_fetch", json!({"url": ""})),
        ("browser", json!({"action": "navigate"})),
        ("process", json!({})),
    ] {
        assert!(
            matches!(
                call(tool, params, json!({})),
                Err(HostError::MissingField { .. })
            ),
            "{tool}"
        );
    }
    let bad_env = call(
        "exec",
        json!({"command": "x", "env": {"A B": "1"}}),
        json!({}),
    );
    assert!(matches!(bad_env, Err(HostError::MalformedArguments { .. })));
    // A relative path with no workspace names no known file.
    let relative = call("read", json!({"path": "a.txt"}), json!({"cwd": null}));
    assert!(matches!(
        relative,
        Err(HostError::MalformedArguments { .. })
    ));
    assert!(call("", json!({}), json!({})).is_err());
    assert!(matches!(
        Host::OpenClaw.parse_request(r#"{"hook_event_name":"after_tool_call","toolName":"x"}"#),
        Err(HostError::WrongEvent(_))
    ));
    assert!(Host::OpenClaw.parse_request("nope").is_err());
}

#[test]
fn the_answer_is_nothing_for_defer_and_a_decision_otherwise() {
    let event = HookEvent::PreToolUse;
    let defer = Decision::new(Verdict::Defer);
    assert_eq!(Host::OpenClaw.render_response(&event, &defer), "");
    for verdict in [Verdict::Allow, Verdict::Ask, Verdict::Deny] {
        // OpenClaw asks through `requireApproval`, so an ask stays an ask.
        let answer = Host::OpenClaw.answer(&event, &Decision::new(verdict));
        assert_eq!(answer.verdict, verdict);
        let doc: Value =
            serde_json::from_str(&Host::OpenClaw.render_response(&event, &answer)).unwrap();
        assert_eq!(doc["decision"], verdict.as_str());
        assert!(doc["reason"].as_str().unwrap().starts_with("moat: "));
    }
}
