//! Cursor integration end to end: `init` writes a fail-closed `hooks.json`,
//! `guard --host cursor` answers in Cursor's permission format.

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, fixture as host_fixture, json, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".cursor"])
}

fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("cursor", payload);
    (out.status.code(), json(&out))
}

fn fixture(name: &str) -> String {
    host_fixture(&format!("cursor/{name}"))
}

#[test]
fn init_installs_fail_closed_hooks_for_every_cursor_event() {
    let sb = sandbox();
    let root: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".cursor/hooks.json")).unwrap())
            .unwrap();
    assert_eq!(root["version"], 1);
    for event in [
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "preToolUse",
    ] {
        let entries = root["hooks"][event]
            .as_array()
            .unwrap_or_else(|| panic!("{event} missing"));
        assert_eq!(entries.len(), 1, "{event}");
        assert_eq!(entries[0]["failClosed"], true, "{event}");
        assert!(
            entries[0]["command"]
                .as_str()
                .unwrap()
                .ends_with("guard --host cursor"),
            "{event}"
        );
    }
    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(OK), "{}", text(&status));
    assert!(text(&status).contains("Cursor"));
    let doctor = text(&sb.moat(&["doctor"]));
    let level = if cfg!(windows) {
        "hook only: Cursor's sandbox runs on macOS and Linux only"
    } else {
        "hook + OS sandbox"
    };
    assert!(
        doctor.contains(&format!("Cursor           protection: {level}")),
        "{doctor}"
    );
    assert!(
        !doctor.contains("is pinned but not this shell's"),
        "{doctor}"
    );
    let again = text(&sb.moat(&["init", "--yes"]));
    assert!(
        again.contains("beforeShellExecution, beforeMCPExecution, beforeReadFile, preToolUse →"),
        "{again}"
    );
}

#[test]
fn shell_exfiltration_is_denied_in_cursor_format() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeShellExecution.json"));
    assert_eq!(code, Some(DENY));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["user_message"].as_str().unwrap();
    assert!(msg.contains("secrets-paths"), "{msg}");
    assert_eq!(doc["agent_message"], doc["user_message"]);
}

#[test]
fn secret_file_read_and_safe_mcp_tool() {
    let sb = sandbox();
    let read = serde_json::json!({
        "conversation_id": "conv-42", "generation_id": "gen-9",
        "hook_event_name": "beforeReadFile", "cursor_version": "2.3.1",
        "workspace_roots": [sb.home.to_string_lossy()],
        "file_path": sb.home.join(".aws").join("credentials").to_string_lossy(),
        "content": "[default]", "attachments": []
    })
    .to_string();
    let (code, doc) = guard(&sb, &read);
    assert_eq!(code, Some(DENY), "{doc}");
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("secrets-paths"),
        "{doc}"
    );

    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution.json"));
    assert_eq!(code, Some(OK));
    assert_eq!(doc["permission"], "allow", "{doc}");
}

#[test]
fn mcp_fetch_to_an_unlisted_host_is_denied() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution-fetch.json"));
    assert_eq!(code, Some(DENY));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["agent_message"].to_string();
    assert!(msg.contains("default.net"), "{msg}");
}

/// A safe-listed tool whose arguments cannot be read must not be judged by
/// its name alone: the path it would read is unknown.
#[test]
fn mcp_arguments_that_do_not_parse_fail_closed() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution-malformed.json"));
    assert_eq!(code, Some(DENY));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["agent_message"].to_string();
    assert!(msg.contains("arguments cannot be checked"), "{msg}");
}

#[test]
fn pre_tool_use_write_inside_the_workspace_is_allowed() {
    let sb = sandbox();
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let payload = serde_json::json!({
        "conversation_id": "c", "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "tool_name": "Write",
        "tool_input": {"file_path": project.join("src/main.rs").to_string_lossy(), "content": ""},
        "tool_use_id": "tu-9"
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(OK));
    assert_eq!(doc["permission"], "allow", "{doc}");

    let (code, doc) = guard(&sb, &fixture("preToolUse-shell.json"));
    assert_eq!(code, Some(OK));
    assert_eq!(doc["permission"], "allow");
    assert!(doc["user_message"].as_str().unwrap().contains("ungoverned"));
}

#[test]
fn pre_tool_use_grep_of_a_secret_is_denied() {
    let sb = sandbox();
    let payload = serde_json::json!({
        "conversation_id": "c", "hook_event_name": "preToolUse",
        "workspace_roots": [sb.home.to_string_lossy()],
        "tool_name": "Grep",
        "tool_input": {"pattern": "aws_secret", "path": sb.home.join(".aws/credentials").to_string_lossy()},
        "tool_use_id": "tu-10"
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(DENY), "{doc}");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("secrets-paths"),
        "{doc}"
    );
}

/// A captured cursor-agent `Grep` names its target with `file_path`, not `path`;
/// reading it as a search of the workspace would let it through.
#[test]
fn pre_tool_use_grep_by_file_path_of_a_secret_is_denied() {
    let sb = sandbox();
    let payload = serde_json::json!({
        "hook_event_name": "preToolUse",
        "workspace_roots": [sb.home.to_string_lossy()],
        "tool_name": "Grep",
        "tool_input": {"file_path": sb.home.join(".aws/credentials").to_string_lossy(), "pattern": "aws_secret"}
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(DENY), "{doc}");
    assert!(
        doc["user_message"].to_string().contains("secrets-paths"),
        "{doc}"
    );
}

/// A tool Cursor does not document is checked against the paths it names
/// instead of passing as ungoverned.
#[test]
fn pre_tool_use_unlisted_search_of_a_secret_is_denied() {
    let sb = sandbox();
    let payload = serde_json::json!({
        "hook_event_name": "preToolUse",
        "workspace_roots": [sb.home.to_string_lossy()],
        "tool_name": "SemanticSearch",
        "tool_input": {"query": "private key", "target_directories": [sb.home.join(".ssh").to_string_lossy()]}
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(DENY), "{doc}");
    assert!(
        doc["user_message"].to_string().contains("secrets-paths"),
        "{doc}"
    );
}

/// A tool outside Cursor's listing and search tools is checked as writing the
/// paths it names, so an editing tool without a write verb in its name cannot
/// change the project's hook file under a read allow.
#[test]
fn pre_tool_use_unlisted_editing_tool_is_checked_as_a_write() {
    let sb = sandbox();
    let project = sb.project();
    let hooks = project.join(".cursor/hooks.json");
    let payload = serde_json::json!({
        "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()],
        "cwd": project.to_string_lossy(),
        "tool_name": "search_replace",
        "tool_input": {"file_path": hooks.to_string_lossy(), "old_string": "a", "new_string": "b"}
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(DENY), "{doc}");
    assert!(
        doc["user_message"].to_string().contains("kernel-self"),
        "{doc}"
    );
}

/// A tool that names no path OpenMoat can check asks (`tool.unknown`), which
/// Cursor's `preToolUse` receives as a deny, instead of passing as ungoverned;
/// a to-do update (`TodoWrite`) stays ungoverned.
/// A policy that sets `tool.unknown: allow` lets it run.
#[test]
fn pre_tool_use_unknown_tool_without_a_path_asks() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("preToolUse-unknown.json"));
    assert_eq!(code, Some(DENY), "{doc}");
    let message = doc["user_message"].to_string();
    assert!(message.contains("default.tool.unknown"), "{doc}");
    assert!(message.contains("RunNotebookCell"), "{doc}");

    // A to-do update touches only the agent's own state and stays ungoverned.
    let todo = fixture("preToolUse-unknown.json").replace(
        r#""tool_name": "RunNotebookCell", "tool_input": { "cell_index": 3 }"#,
        r#""tool_name": "TodoWrite", "tool_input": { "todos": [{ "content": "x", "status": "pending" }] }"#,
    );
    assert!(todo.contains("TodoWrite"));
    let (code, doc) = guard(&sb, &todo);
    assert_eq!(code, Some(OK), "{doc}");
    assert_eq!(doc["permission"], "allow", "{doc}");
    assert!(
        doc["user_message"].to_string().contains("ungoverned"),
        "{doc}"
    );

    std::fs::write(
        sb.home.join(".moat/policy.yaml"),
        "version: 1\ndefaults: { '*': ask, tool.unknown: allow }\n",
    )
    .unwrap();
    let accept = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accept).contains("re-pinned"), "{}", text(&accept));
    let (code, doc) = guard(&sb, &fixture("preToolUse-unknown.json"));
    assert_eq!(code, Some(OK), "{doc}");
    assert_eq!(doc["permission"], "allow", "{doc}");
}

fn write_payload(sb: &Sandbox, path: &std::path::Path) -> String {
    let project = sb.project();
    serde_json::json!({
        "conversation_id": "cur-s1", "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "tool_name": "Write",
        "tool_input": {"file_path": path.to_string_lossy(), "content": "x"},
        "tool_use_id": "tu-11"
    })
    .to_string()
}

/// Cursor runs a `preToolUse` call answered `ask` ("accepted by the schema but
/// not enforced"), so moat sends a deny that says how to approve it, and records
/// the `ask`; `moat allow --last` then approves that exact file for the
/// conversation.
#[test]
fn pre_tool_use_ask_is_denied_and_allow_last_approves_the_file() {
    let sb = sandbox();
    let notes = sb.home.join("notes").join("todo.md");
    let (code, doc) = guard(&sb, &write_payload(&sb, &notes));
    assert_eq!(code, Some(DENY), "{doc}");
    assert_eq!(doc["permission"], "deny");
    let message = doc["agent_message"].to_string();
    assert!(message.contains("run `moat`"), "{doc}");
    assert!(message.contains("moat allow --last"), "{doc}");
    let log = text(&sb.moat(&["audit", "export"]));
    assert!(log.contains("\"verdict\":\"ask\""), "{log}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
    assert!(text(&allow).contains("may write"), "{}", text(&allow));
    let (code, doc) = guard(&sb, &write_payload(&sb, &notes));
    assert_eq!(code, Some(OK), "{doc}");
    assert_eq!(doc["permission"], "allow", "{doc}");
    let other = sb.home.join("notes").join("other.md");
    let (code, _) = guard(&sb, &write_payload(&sb, &other));
    assert_eq!(code, Some(DENY), "only the approved file");
}

/// Cursor prompts on a `beforeShellExecution` `ask`, so it keeps the `ask`, and
/// `moat allow --last` approves the command for the conversation.
#[test]
fn shell_ask_stays_an_ask_and_allow_last_approves_it() {
    let sb = sandbox();
    let project = sb.project();
    let payload = serde_json::json!({
        "conversation_id": "cur-s2", "hook_event_name": "beforeShellExecution",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "command": "git config core.pager less"
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(
        (code, &doc["permission"]),
        (Some(OK), &Value::from("ask")),
        "{doc}"
    );
    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(
        (code, &doc["permission"]),
        (Some(OK), &Value::from("allow")),
        "{doc}"
    );
}

#[test]
fn unknown_cursor_event_fails_closed() {
    let sb = sandbox();
    let (code, doc) = guard(
        &sb,
        r#"{"hook_event_name":"afterFileEdit","file_path":"/p/x"}"#,
    );
    assert_eq!(code, Some(DENY));
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("kernel-error")
    );
}
