use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use super::{bench, parse, render, tools};
use crate::bench::Answer;
use crate::{Host, HostError};

fn payload(name: &str, args: &Value) -> String {
    json!({
        "conversationId": "conv-1", "workspacePaths": ["/p", "/q"],
        "transcriptPath": "/t", "artifactDirectoryPath": "/a", "modelName": "m",
        "lastUserInput": "go", "toolCall": { "name": name, "args": args }, "stepIdx": 3,
    })
    .to_string()
}

fn action(name: &str, args: &Value) -> Option<Action> {
    parse(Host::AntigravityCli, &payload(name, args)).unwrap().action
}

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/src/host/antigravity_cli/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn the_payload_gives_session_step_and_working_directory() {
    let request = parse(
        Host::AntigravityCli,
        &payload("view_file", &json!({"AbsolutePath": "/p/a"})),
    )
    .unwrap();
    assert_eq!(request.session_id, "conv-1");
    assert_eq!(request.call_id.as_deref(), Some("3"));
    assert_eq!(request.cwd.as_deref(), Some("/p"));
    assert_eq!(request.tool, "view_file");
}

#[test]
fn every_documented_file_tool_maps_to_what_it_touches() {
    let read = |path: &str| Action::FsRead {
        path: path.to_owned(),
    };
    assert_eq!(action("view_file", &json!({"AbsolutePath": "/p/a"})), Some(read("/p/a")));
    assert_eq!(action("list_dir", &json!({"DirectoryPath": "/p"})), Some(read("/p")));
    for tool in ["write_to_file", "replace_file_content", "multi_replace_file_content"] {
        assert_eq!(
            action(tool, &json!({"TargetFile": "/p/a"})),
            Some(Action::FsWrite { path: "/p/a".to_owned() }),
            "{tool}"
        );
    }
    let request = parse(
        Host::AntigravityCli,
        &payload("write_to_file", &json!({"TargetFile": "/p/a", "CodeContent": "x"})),
    )
    .unwrap();
    assert_eq!(request.content.as_deref(), Some("x"));
    let edit = parse(
        Host::AntigravityCli,
        &payload(
            "replace_file_content",
            &json!({"TargetFile": "/p/a", "TargetContent": "a", "ReplacementContent": "b",
                "AllowMultiple": true}),
        ),
    )
    .unwrap();
    assert_eq!(edit.edits.len(), 1);
    assert!(edit.edits[0].all);
}

#[test]
fn searches_read_what_their_patterns_reach() {
    assert_eq!(
        action("find_by_name", &json!({"SearchDirectory": "/p", "Pattern": "*.rs"})),
        Some(Action::FsRead { path: "/p".to_owned() })
    );
    match action("find_by_name", &json!({"SearchDirectory": "/p", "Pattern": "../../etc/*"})) {
        Some(Action::ReadFiles { paths }) => assert!(paths.iter().any(|p| p.contains("..")), "{paths:?}"),
        other => panic!("{other:?}"),
    }
    match action("grep_search", &json!({"SearchPath": "sub", "Query": "x", "Includes": ["/etc/*"]})) {
        Some(Action::ReadFiles { paths }) => {
            assert!(paths.contains(&"/p/sub".to_owned()), "{paths:?}");
            assert!(paths.contains(&"/etc".to_owned()), "{paths:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn network_tools_map_to_fetch_and_search() {
    assert_eq!(
        action("read_url_content", &json!({"Url": "https://a.example/x"})),
        Some(Action::Fetch { url: "https://a.example/x".to_owned() })
    );
    assert_eq!(
        action("search_web", &json!({"query": "q", "domain": "a.example"})),
        Some(Action::WebSearch { query: "q".to_owned() })
    );
}

#[test]
fn a_command_runs_where_it_says_and_a_named_terminal_needs_review() {
    let map = |args: &Value| tools::map_on("run_command", args, Some("/p"), false).unwrap().action;
    assert_eq!(
        map(&json!({"CommandLine": "ls", "Cwd": "/q"})),
        Some(Action::Shell { command: "cd '/q' && ls".to_owned() })
    );
    assert!(matches!(
        map(&json!({"CommandLine": "ls", "RequestedTerminalID": "t1"})),
        Some(Action::Unchecked { .. })
    ));
    let windows =
        tools::map_on("run_command", &json!({"CommandLine": "dir"}), Some("/p"), true).unwrap();
    assert!(matches!(windows.action, Some(Action::ForeignShell { .. })));
}

#[test]
fn typed_input_and_later_agents_need_review() {
    let held = |tool: &str, args: Value| assert!(
        matches!(action(tool, &args), Some(Action::Unchecked { .. })),
        "{tool}"
    );
    held("manage_task", json!({"Action": "send_input", "TaskId": "t", "Input": "ls\n"}));
    held("schedule", json!({"Prompt": "later", "DurationSeconds": 60}));
    held("define_subagent", json!({"name": "x", "system_prompt": "y"}));
    held("invoke_subagent", json!({"Subagents": [{"Prompt": "go", "Workspace": "/p"}]}));
}

#[test]
fn tools_that_touch_nothing_are_ungoverned() {
    for (tool, args) in [
        ("ask_question", json!({"questions": []})),
        ("list_permissions", json!({})),
        ("ask_permission", json!({"Action": "command", "Target": "x", "Reason": "y"})),
        ("manage_task", json!({"Action": "list"})),
        ("manage_task", json!({"Action": "status", "TaskId": "t"})),
        ("manage_task", json!({"Action": "kill", "TaskId": "t"})),
        ("manage_subagents", json!({"Action": "kill_all"})),
    ] {
        assert_eq!(action(tool, &args), None, "{tool}");
    }
}

#[test]
fn an_unlisted_tool_is_unknown_not_allowed() {
    for tool in ["send_message", "browser_click", "future_tool"] {
        assert!(
            matches!(action(tool, &json!({"x": "/p/y"})), Some(Action::UnknownTool { .. })),
            "{tool}"
        );
    }
    assert!(matches!(
        action("generate_image", &json!({"Prompt": "a"})),
        Some(Action::UnknownTool { .. })
    ));
    assert!(matches!(
        action("manage_task", &json!({"Action": "other"})),
        Some(Action::UnknownTool { .. })
    ));
}

#[test]
fn generated_images_read_their_input_paths() {
    assert_eq!(
        action("generate_image", &json!({"Prompt": "a", "ImagePaths": ["/p/a.png"]})),
        Some(Action::ReadFiles { paths: vec!["/p/a.png".to_owned()] })
    );
}

#[test]
fn mcp_tools_are_traced_to_their_server() {
    let request = parse(
        Host::AntigravityCli,
        &payload(
            "call_mcp_tool",
            &json!({"ServerName": "gh", "ToolName": "issues", "Arguments": {"q": "x"}}),
        ),
    )
    .unwrap();
    assert_eq!(request.tool, "mcp__gh__issues");
    assert!(matches!(request.action, Some(Action::McpTool { .. })));
    let eager = action("mcp_gh_issues", &json!({"q": "x"}));
    assert!(matches!(eager, Some(Action::McpTool { .. })), "{eager:?}");
}

#[test]
fn a_missing_or_malformed_field_is_an_error() {
    for (tool, args) in [
        ("view_file", json!({})),
        ("run_command", json!({"CommandLine": ""})),
        ("find_by_name", json!({"Pattern": "*"})),
        ("grep_search", json!({"Query": "x"})),
        ("manage_task", json!({})),
        ("call_mcp_tool", json!({"ServerName": "x"})),
    ] {
        let error = parse(Host::AntigravityCli, &payload(tool, &args)).err();
        assert!(matches!(error, Some(HostError::MissingField { .. })), "{tool}: {error:?}");
    }
    assert!(parse(Host::AntigravityCli, "{not json").is_err());
    let unnamed = json!({"toolCall": {"name": "", "args": {}}}).to_string();
    assert!(parse(Host::AntigravityCli, &unnamed).is_err());
}

#[test]
fn other_events_are_refused() {
    let post = json!({"toolCall": {"name": "view_file", "args": {}}, "error": ""}).to_string();
    assert!(matches!(parse(Host::AntigravityCli, &post), Err(HostError::WrongEvent(_))));
    let start = json!({"conversationId": "c"}).to_string();
    assert!(matches!(parse(Host::AntigravityCli, &start), Err(HostError::WrongEvent(_))));
    // The envelope names an event: another host's payload.
    let named = json!({"hook_event_name": "PreToolUse", "tool_name": "x"}).to_string();
    assert!(Host::AntigravityCli.parse_request(&named).is_err());
}

#[test]
fn verdicts_use_only_documented_decisions_and_never_auto_approve() {
    let reply = |verdict: Verdict| -> Value {
        let mut decision = Decision::new(verdict);
        decision.reasons.push("because".to_owned());
        serde_json::from_str(&render(&decision)).unwrap()
    };
    assert_eq!(reply(Verdict::Deny)["decision"], "deny");
    assert_eq!(reply(Verdict::Review)["decision"], "force_ask");
    assert!(reply(Verdict::Review)["reason"].as_str().unwrap().contains("because"));
    assert_eq!(reply(Verdict::Allow), json!({"decision": "allow"}));
    assert_eq!(reply(Verdict::Defer), json!({"decision": "allow"}));
    for verdict in [Verdict::Allow, Verdict::Deny, Verdict::Review, Verdict::Defer] {
        assert!(reply(verdict).get("overwrite").is_none());
    }
}

#[test]
fn bench_reads_the_same_decisions_it_renders() {
    assert_eq!(bench::seen(Verdict::Defer), Answer::Passthrough);
    assert_eq!(bench::seen(Verdict::Allow), Answer::Passthrough);
    assert_eq!(bench::seen(Verdict::Deny), Answer::Deny);
    assert_eq!(bench::seen(Verdict::Review), Answer::Review);
}

#[test]
fn fixtures_parse_as_documented() {
    for name in [
        "run_command.json",
        "view_file.json",
        "write_to_file.json",
        "replace_file_content.json",
        "multi_replace_file_content.json",
        "list_dir.json",
        "find_by_name.json",
        "grep_search.json",
        "read_url_content.json",
        "search_web.json",
        "manage_task-send_input.json",
        "schedule.json",
        "define_subagent.json",
        "invoke_subagent.json",
        "send_message.json",
        "manage_subagents.json",
        "ask_question.json",
        "generate_image.json",
        "call_mcp_tool.json",
        "mcp_eager.json",
        "future-tool.json",
    ] {
        let request = parse(Host::AntigravityCli, &fixture(name)).unwrap();
        assert_eq!(request.session_id, "conv-1", "{name}");
    }
    assert!(parse(Host::AntigravityCli, &fixture("view_file-malformed.json")).is_err());
}
