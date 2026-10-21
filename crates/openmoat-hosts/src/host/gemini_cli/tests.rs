use openmoat_core::{Action, Decision, Verdict};
use serde_json::{Value, json};

use super::tools::map_on;
use crate::{HookEvent, HookRequest, Host, HostError};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/hosts/gemini-cli"
);

fn fixture(name: &str) -> Result<HookRequest, HostError> {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap();
    Host::GeminiCli.parse_request(&text)
}

fn action(name: &str) -> Option<Action> {
    fixture(name).unwrap().action
}

fn call(tool: &str, input: Value) -> Result<HookRequest, HostError> {
    let mut payload = json!({
        "session_id": "s-1", "cwd": "/p", "hook_event_name": "BeforeTool", "tool_name": tool,
    });
    payload["tool_input"] = input;
    Host::GeminiCli.parse_request(&payload.to_string())
}

fn read(path: &str) -> Action {
    Action::FsRead {
        path: path.to_owned(),
    }
}

fn unknown(tool: &str) -> Action {
    Action::UnknownTool {
        host: "gemini-cli".to_owned(),
        tool: tool.to_owned(),
    }
}

#[test]
fn a_shell_command_runs_in_its_dir_path() {
    let shell = fixture("run_shell_command").unwrap();
    assert_eq!(shell.session_id, "8f0d5c1e-3b2a-4c6d-9e7f-0a1b2c3d4e5f");
    assert_eq!(shell.cwd.as_deref(), Some("/p"));
    assert_eq!(shell.event, HookEvent::PreToolUse);
    assert_eq!(shell.call_id, None);
    let in_dir = fixture("run_shell_command-dir_path").unwrap();
    assert_eq!(in_dir.cwd.as_deref(), Some("/p/app"));
    let absolute = call(
        "run_shell_command",
        json!({"command": "ls", "dir_path": "/srv"}),
    );
    assert_eq!(absolute.unwrap().cwd.as_deref(), Some("/srv"));
    // Gemini CLI runs commands with PowerShell on Windows, which is never classified.
    let input = json!({"command": "Get-ChildItem"});
    let windows = map_on("run_shell_command", &input, None, Some("/p"), true).unwrap();
    assert!(matches!(windows.action, Some(Action::ForeignShell { .. })));
    let posix = map_on("run_shell_command", &input, None, Some("/p"), false).unwrap();
    assert!(matches!(posix.action, Some(Action::Shell { .. })));
}

#[test]
fn file_tools_read_and_write_the_paths_they_name() {
    assert_eq!(
        action("read_file"),
        Some(read("/home/dev/.aws/credentials"))
    );
    let write = fixture("write_file").unwrap();
    assert_eq!(
        write.action,
        Some(Action::FsWrite {
            path: "/p/src/main.rs".into()
        })
    );
    assert_eq!(write.content.as_deref(), Some("fn main() {}\n"));
    let replace = fixture("replace-settings").unwrap();
    assert_eq!(
        replace.action,
        Some(Action::FsWrite {
            path: "/home/dev/.gemini/settings.json".into()
        })
    );
    assert_eq!(replace.content, None, "replace changes part of the file");
    assert_eq!(action("list_directory"), Some(read("/p/src")));
}

#[test]
fn searches_read_their_directory_and_where_the_pattern_climbs_to() {
    assert_eq!(action("grep_search"), Some(read("/home/dev/.aws")));
    let legacy = call("search_file_content", json!({"pattern": "x"})).unwrap();
    assert_eq!(legacy.action, Some(read("/p")));
    assert_eq!(
        action("glob"),
        Some(Action::ReadFiles {
            paths: vec!["/p/src".into(), "/p/src/../../home/dev/.ssh".into()]
        })
    );
    let absolute = call("glob", json!({"pattern": "/etc/**/*.conf"})).unwrap();
    assert_eq!(
        absolute.action,
        Some(Action::ReadFiles {
            paths: vec!["/p".into(), "/etc".into()]
        })
    );
    let plain = call("glob", json!({"pattern": "**/*.rs"})).unwrap();
    assert_eq!(plain.action, Some(read("/p")));
}

#[test]
fn read_many_files_reads_each_include_up_to_its_first_wildcard() {
    assert_eq!(
        action("read_many_files"),
        Some(Action::ReadFiles {
            paths: vec![
                "README.md".into(),
                "docs".into(),
                "/p".into(),
                "/home/dev/.ssh".into(),
            ]
        })
    );
    for bad in [json!({}), json!({"include": []}), json!({"include": [7]})] {
        assert!(
            matches!(
                call("read_many_files", bad.clone()),
                Err(HostError::MalformedArguments { .. })
            ),
            "{bad}"
        );
    }
}

#[test]
fn web_fetch_reads_the_urls_in_its_prompt() {
    // a GitHub page is fetched from raw.githubusercontent.com
    assert_eq!(
        action("web_fetch"),
        Some(Action::Fetch {
            url: "https://raw.githubusercontent.com/example/repo/main/README.md".into()
        })
    );
    // one action names one URL: several are refused, never half-checked
    let two = call(
        "web_fetch",
        json!({"prompt": "compare https://a.example/ and https://b.example/"}),
    );
    let Err(HostError::MalformedArguments { problem, .. }) = two else {
        panic!("{two:?}");
    };
    assert!(
        problem.contains("fetch each URL in a call of its own"),
        "{problem}"
    );
    assert!(matches!(
        call("web_fetch", json!({"prompt": "no link here"})),
        Err(HostError::MalformedArguments { .. })
    ));
    assert_eq!(
        action("google_web_search"),
        Some(Action::WebSearch {
            query: "rust serde untagged enum".into()
        })
    );
}

#[test]
fn an_mcp_tool_is_named_from_its_context() {
    let mcp = fixture("mcp").unwrap();
    assert_eq!(mcp.tool, "mcp__files__read_text_file");
    let Some(Action::McpTool { name, reads, .. }) = mcp.action else {
        panic!("{:?}", mcp.action);
    };
    assert_eq!(name, "mcp__files__read_text_file");
    assert_eq!(reads, vec!["/home/dev/.aws/credentials".to_owned()]);
    // without the context the server cannot be told from the tool's name
    let bare = call("mcp_files_read_text_file", json!({"path": "/x"})).unwrap();
    assert_eq!(bare.action, Some(unknown("mcp_files_read_text_file")));
}

#[test]
fn mcp_resources_are_read_as_files_or_unknown() {
    let file = call(
        "read_mcp_resource",
        json!({"uri": "file:///home/dev/.npmrc"}),
    )
    .unwrap();
    assert_eq!(file.action, Some(read("/home/dev/.npmrc")));
    let other = call("read_mcp_resource", json!({"uri": "db://orders"})).unwrap();
    assert_eq!(other.action, Some(unknown("read_mcp_resource")));
    assert!(call("read_mcp_resource", json!({"uri": "file:relative"})).is_err());
}

#[test]
fn agent_state_tools_are_ungoverned_and_others_unknown() {
    assert_eq!(action("write_todos"), None);
    for tool in [
        "ask_user",
        "activate_skill",
        "codebase_investigator",
        "invoke_agent",
    ] {
        assert_eq!(call(tool, json!({})).unwrap().action, None, "{tool}");
    }
    assert_eq!(action("unknown-tool"), Some(unknown("deploy_preview")));
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
    assert!(call("", json!({})).is_err());
    let after = json!({"hook_event_name": "AfterTool", "tool_name": "read_file"});
    assert!(matches!(
        Host::GeminiCli.parse_request(&after.to_string()),
        Err(HostError::WrongEvent(_))
    ));
    assert!(matches!(
        call("read_file", json!({"file_path": 7})),
        Err(HostError::MissingField { .. })
    ));
}

#[test]
fn replies_are_gemini_decisions() {
    let host = Host::GeminiCli;
    let event = HookEvent::PreToolUse;
    assert_eq!(
        host.render_response(&event, &Decision::new(Verdict::Defer)),
        ""
    );
    let allow: Value =
        serde_json::from_str(&host.render_response(&event, &Decision::new(Verdict::Allow)))
            .unwrap();
    assert_eq!(allow, json!({"decision": "allow"}));
    let mut deny = Decision::new(Verdict::Deny);
    deny.rules.push("secrets-paths".into());
    let doc: Value = serde_json::from_str(&host.render_response(&event, &deny)).unwrap();
    assert_eq!(doc["decision"], "deny");
    assert_eq!(doc["reason"], "moat: deny [secrets-paths]");
    assert_eq!(doc["systemMessage"], doc["reason"]);
    // Gemini CLI asks the person itself, so an `ask` stays an `ask`.
    let ask = host.answer(&event, &Decision::new(Verdict::Ask));
    assert_eq!(ask.verdict, Verdict::Ask);
    let doc: Value = serde_json::from_str(&host.render_response(&event, &ask)).unwrap();
    assert_eq!(doc["decision"], "ask");
}
