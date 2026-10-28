use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use crate::{HookEvent, HookRequest, Host, HostError};

mod v2;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host/opencode/fixtures");

fn fixture(name: &str) -> HookRequest {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::OpenCode.parse_request(&text).unwrap()
}

/// A payload for `tool` with `args` in `/p`, with `extra` fields over it.
fn call(tool: &str, args: Value, extra: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "hook_event_name": "tool.execute.before",
        "tool": tool,
        "sessionID": "ses_1",
        "callID": "call-1",
        "directory": "/p",
        "worktree": "/p",
        "mcpServers": [],
        "platform": "darwin",
    });
    payload["args"] = args;
    if let (Value::Object(base), Value::Object(extra)) = (&mut payload, extra) {
        base.extend(extra);
    }
    Host::OpenCode.parse_request(&payload.to_string())
}

fn action(tool: &str, args: Value) -> Option<Action> {
    call(tool, args, json!({})).unwrap().action
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

fn mcp_name(request: &HookRequest) -> Option<&str> {
    match &request.action {
        Some(Action::McpTool { name, .. }) => Some(name),
        _ => None,
    }
}

#[test]
fn bash_is_a_shell_command_in_its_workdir() {
    let bash = fixture("bash");
    assert_eq!(bash.session_id, "ses_5b2f0c1e9ffeAbCdEfGhIjKlMn");
    assert_eq!(bash.call_id.as_deref(), Some("toolu_bash_1"));
    assert_eq!(bash.cwd.as_deref(), Some("/p"));
    // OpenCode 1 cannot ask.
    assert_eq!(bash.event, HookEvent::PreToolUseNoAsk);
    // On Windows the shell may be Git Bash, PowerShell or `cmd`, and a guard
    // built for Windows reads every call as Windows' whatever `platform` says.
    assert!(matches!(
        fixture("bash-windows").action,
        Some(Action::ForeignShell { command, .. }) if command == "Get-ChildItem"
    ));
    if cfg!(windows) {
        assert!(matches!(bash.action, Some(Action::ForeignShell { .. })));
        return;
    }
    assert_eq!(
        bash.action,
        Some(Action::Shell {
            command: "cargo test --workspace".into()
        })
    );
    assert_eq!(
        fixture("bash-workdir").action,
        Some(Action::Shell {
            command: "cd 'crates/core' && cat ../notes.txt".into()
        })
    );
    assert_eq!(
        action("bash", json!({"command": "ls", "workdir": "it's"})),
        Some(Action::Shell {
            command: r"cd 'it'\''s' && ls".into()
        })
    );
}

#[test]
fn file_tools_open_their_path_joined_to_the_directory() {
    assert_eq!(fixture("read").action, read("/p/src/main.rs"));
    assert_eq!(
        fixture("read-secret").action,
        read("/Users/me/.ssh/id_ed25519")
    );
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
            path: "/p/src/lib.rs".into()
        })
    );
    assert_eq!(edit.content, None);
    assert_eq!(
        fixture("edit-plugin").action,
        Some(Action::FsWrite {
            path: "/Users/me/.config/opencode/plugins/openmoat.js".into()
        })
    );
    // OpenCode expands no `~`: the path is one in the directory.
    assert_eq!(
        action("read", json!({"filePath": "~/.ssh/id_rsa"})),
        read("/p/~/.ssh/id_rsa")
    );
    assert_eq!(
        action(
            "lsp",
            json!({"operation": "hover", "filePath": "src/a.rs", "line": 1, "character": 1})
        ),
        read("/p/src/a.rs")
    );
    assert_eq!(
        fixture("apply_patch").action,
        Some(Action::Patch {
            writes: vec!["/p/src/a.rs".into(), "/p/docs/b.md".into()]
        })
    );
}

#[test]
fn windows_paths_are_absolute_as_node_reads_them() {
    let windows = |path: &str| {
        call("read", json!({"filePath": path}), json!({"platform": "win32", "directory": "C:/p"}))
            .unwrap()
            .action
    };
    assert_eq!(windows(r"C:\Users\me\.ssh\id_rsa"), read(r"C:\Users\me\.ssh\id_rsa"));
    assert_eq!(windows("src/a.rs"), read("C:/p/src/a.rs"));
    // `C:x` is relative to the drive's working directory, not absolute.
    assert_eq!(windows("C:x"), read("C:/p/C:x"));
}

#[test]
fn search_tools_read_their_path_or_the_directory() {
    assert_eq!(fixture("glob").action, read("/p"));
    assert_eq!(
        fixture("glob-climbs").action,
        Some(Action::ReadFiles {
            paths: vec!["/p/crates".into(), "/p/crates/../../.env".into()]
        })
    );
    assert_eq!(fixture("grep").action, read("/p/src"));
    assert_eq!(
        action("glob", json!({"pattern": "/etc/**/*.conf"})),
        Some(Action::ReadFiles {
            paths: vec!["/p".into(), "/etc".into()]
        })
    );
    let no_directory = call("grep", json!({"pattern": "x"}), json!({"directory": ""}));
    assert!(matches!(
        no_directory,
        Err(HostError::MalformedArguments { .. })
    ));
}

#[test]
fn web_tools_fetch_and_search() {
    assert_eq!(
        fixture("webfetch").action,
        Some(Action::Fetch {
            url: "https://docs.rs/serde".into()
        })
    );
    assert_eq!(
        fixture("websearch").action,
        Some(Action::WebSearch {
            query: "serde json flatten".into()
        })
    );
}

/// OpenCode names an MCP tool `<server>_<tool>`; the configured servers the
/// plugin sends tell it from a plugin's tool.
#[test]
fn mcp_tools_are_named_by_the_configured_server() {
    let mcp = fixture("mcp");
    assert_eq!(mcp_name(&mcp), Some("mcp__github__create_issue"));
    assert_eq!(mcp.tool, "github_create_issue");
    // Two servers' spellings begin the name: the longest wins, as OpenCode's
    // Code Mode splits it.
    assert_eq!(
        mcp_name(&fixture("mcp-ambiguous")),
        Some("mcp__files_read__file")
    );
    // A server name with characters OpenCode replaces.
    let spelled = call(
        "my_db_query",
        json!({}),
        json!({"mcpServers": ["my.db"]}),
    )
    .unwrap();
    assert_eq!(mcp_name(&spelled), Some("mcp__my.db__query"));
    assert!(matches!(
        fixture("read_mcp_resource").action,
        Some(Action::McpTool { name, reads, .. })
            if name == "mcp__filesystem__read_resource"
                && reads == vec!["/Users/me/.aws/credentials".to_owned()]
    ));
}

/// A tool no configured server's name begins (a plugin's, a custom tool's,
/// or an MCP tool the plugin could not name) is decided as an MCP tool of its
/// own name, with what its arguments name checked.
#[test]
fn any_other_tool_is_checked_by_its_arguments() {
    let Some(Action::McpTool { name, reads, .. }) = fixture("plugin-tool").action else {
        panic!("not an MCP tool");
    };
    assert_eq!(name, "deploy_preview");
    assert!(reads.contains(&"/Users/me/.ssh/id_rsa".to_owned()), "{reads:?}");
}

#[test]
fn tools_that_touch_nothing_are_ungoverned() {
    assert_eq!(fixture("task").action, None);
    for tool in ["todowrite", "skill", "question", "invalid", "execute", "list_mcp_resources"] {
        assert_eq!(action(tool, json!({})), None, "{tool}");
    }
}

#[test]
fn malformed_and_foreign_payloads_are_errors() {
    let text = std::fs::read_to_string(format!("{FIXTURES}/read-malformed.json")).unwrap();
    assert!(matches!(
        Host::OpenCode.parse_request(&text),
        Err(HostError::MissingField { field: "filePath", .. })
    ));
    assert!(matches!(
        call("bash", json!({}), json!({})),
        Err(HostError::MissingField {
            field: "command",
            ..
        })
    ));
    assert!(matches!(
        call("bash", json!({"command": "ls", "workdir": 3}), json!({})),
        Err(HostError::MalformedArguments { .. })
    ));
    assert!(matches!(
        call("read", json!({"filePath": "a"}), json!({"directory": null})),
        Err(HostError::MalformedArguments { .. })
    ));
    assert!(matches!(
        call("", json!({}), json!({})),
        Err(HostError::MissingField { field: "tool", .. })
    ));
    assert!(Host::OpenCode.parse_request("{").is_err());
    let after = json!({"hook_event_name": "tool.execute.after", "tool": "bash",
        "args": {"command": "ls"}});
    assert!(matches!(
        Host::OpenCode.parse_request(&after.to_string()),
        Err(HostError::WrongEvent(event)) if event == "tool.execute.after"
    ));
}

/// OpenCode 1 cannot ask: an ask is a deny that says how to approve it; a
/// defer prints nothing.
#[test]
fn an_ask_is_a_deny_and_a_defer_prints_nothing() {
    let event = fixture("read").event;
    assert_eq!(event, HookEvent::PreToolUseNoAsk);
    let mut ask = Decision::new(Verdict::Ask);
    ask.rules.push("runs-later".to_owned());
    let answered = Host::OpenCode.answer(&event, &ask);
    assert_eq!(answered.verdict, Verdict::Deny);
    let reply: Value = serde_json::from_str(&Host::OpenCode.render_response(&event, &answered)).unwrap();
    assert_eq!(reply["decision"], "deny");
    let reason = reply["reason"].as_str().unwrap();
    assert!(reason.contains("openmoat allow --last"), "{reason}");
    assert!(reason.contains("OpenCode 1"), "{reason}");
    let defer = Decision::new(Verdict::Defer);
    assert_eq!(Host::OpenCode.render_response(&event, &defer), "");
    let allow: Value =
        serde_json::from_str(&Host::OpenCode.render_response(&event, &Decision::new(Verdict::Allow)))
            .unwrap();
    assert_eq!(allow["decision"], "allow");
}

/// Every payload fixture parses, so none of them is stale.
#[test]
fn every_fixture_but_the_malformed_one_parses() {
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if path.extension().is_some_and(|e| e == "json") && !name.ends_with("read-malformed") {
            let _ = fixture(&name);
        }
    }
}

#[test]
fn the_plugin_names_the_host_and_waits_as_long_as_the_spec_says() {
    let source = include_str!("integration/openmoat.js");
    assert!(source.starts_with("// OpenMoat for OpenCode."));
    assert!(source.contains(r#"["guard", "--host", "opencode"]"#));
    assert!(source.contains(&format!(
        "const GUARD_TIMEOUT_MS = {}_000;",
        super::HOOK_TIMEOUT_S
    )));
    assert!(source.contains(r#"hook_event_name: "tool.execute.before""#));
    assert!(source.contains(r#"hook_event_name: "execute.before""#));
    // One file for both versions: OpenCode 1 calls `server`, OpenCode 2 `setup`.
    assert!(source.contains(r#"export default { id: "openmoat", server, setup };"#));
}

/// A read of another agent's folder asks under the default policy
/// (`protected-contents`, ADR-038); OpenCode 1 cannot ask, so it is a deny that
/// names the rule and how to approve it. Through the `read` tool, which is
/// checked on every OS (OpenCode's shell on Windows is left to OpenCode).
#[test]
fn a_copy_of_an_agent_folder_is_denied_with_the_allow_hint() {
    let policy = openmoat_core::Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
    let ctx = openmoat_core::EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let compiled = openmoat_core::CompiledPolicy::compile(&policy, &ctx).unwrap();
    let request = call("read", json!({"filePath": "/Users/me/.codex"}), json!({})).unwrap();
    let decision = compiled.decide(request.action.as_ref().unwrap());
    assert_eq!(decision.verdict, Verdict::Ask);
    assert_eq!(decision.rules, [openmoat_core::HOLDS_PROTECTED_RULE]);
    let event = request.event;
    let answered = Host::OpenCode.answer(&event, &decision);
    assert_eq!(answered.verdict, Verdict::Deny);
    let reply: Value =
        serde_json::from_str(&Host::OpenCode.render_response(&event, &answered)).unwrap();
    let reason = reply["reason"].as_str().unwrap();
    assert!(reason.contains("openmoat allow --last"), "{reason}");
    assert!(reason.contains("/Users/me/.codex"), "{reason}");
}
