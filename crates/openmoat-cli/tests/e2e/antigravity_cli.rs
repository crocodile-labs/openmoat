//! Antigravity CLI end to end: `init` adds one named entry to
//! `~/.gemini/config/hooks.json`, `guard --host antigravity-cli` answers with
//! its `decision`, and `uninstall` gives the file back.
//!
//! The payloads are built from the documented shape
//! (`crates/openmoat-hosts/src/host/antigravity_cli/fixtures/README.md`), not
//! captured from a running `agy`.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, fixture, json as parse, text};

/// The directory that tells OpenMoat the CLI is installed.
pub(crate) const DIR: &str = ".gemini/antigravity-cli";

/// A hook file as a person keeps it, with another hook in it.
pub(crate) const ORIGINAL: &str =
    "{\n  \"lint\": {\n    \"enabled\": true,\n    \"PostToolUse\": []\n  }\n}\n";

fn hook_file(sb: &Sandbox) -> PathBuf {
    sb.home.join(".gemini/config/hooks.json")
}

/// A `PreToolUse` payload for `tool` with `args`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, args: &Value) -> String {
    json!({
        "conversationId": "conv-1", "workspacePaths": [sb.project().to_string_lossy()],
        "transcriptPath": "", "artifactDirectoryPath": "", "modelName": "m",
        "lastUserInput": "go", "toolCall": { "name": tool, "args": args }, "stepIdx": 1,
    })
    .to_string()
}

fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("antigravity-cli", payload);
    (out.status.code(), parse(&out))
}

fn status(sb: &Sandbox) -> Value {
    let doc = parse(&sb.moat(&["status", "--format", "json"]));
    doc["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["host"] == "antigravity-cli")
        .unwrap()
        .clone()
}

#[test]
fn init_adds_one_named_entry_and_is_idempotent() {
    let sb = Sandbox::bare(&[DIR]);
    fs::create_dir_all(hook_file(&sb).parent().unwrap()).unwrap();
    fs::write(hook_file(&sb), ORIGINAL).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let root: Value = serde_json::from_str(&fs::read_to_string(hook_file(&sb)).unwrap()).unwrap();
    assert_eq!(root["lint"]["enabled"], true, "{root}");
    assert_eq!(root["openmoat"]["enabled"], true, "{root}");
    let entries = root["openmoat"]["PreToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{root}");
    assert_eq!(entries[0]["matcher"], "*");
    let hook = &entries[0]["hooks"][0];
    assert_eq!(hook["timeout"], 600);
    let command = hook["command"].as_str().unwrap();
    assert!(
        command.contains(" guard --host antigravity-cli --home "),
        "{hook}"
    );

    let before = fs::read_to_string(hook_file(&sb)).unwrap();
    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert_eq!(fs::read_to_string(hook_file(&sb)).unwrap(), before);
    assert_eq!(status(&sb)["level"], "hook-only", "{}", status(&sb));
}

#[test]
fn a_secret_read_is_denied_in_its_own_format() {
    if cfg!(windows) {
        return;
    }
    let sb = Sandbox::installed(&[DIR]);
    let (code, reply) = guard(&sb, &fixture("antigravity-cli/run_command.json"));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");
    assert!(
        reply["reason"].to_string().contains("secrets-paths"),
        "{reply}"
    );
}

#[test]
fn allow_review_and_defer_reach_it_as_its_own_decisions() {
    let sb = Sandbox::installed(&[DIR]);
    let file = sb.project().join("a.txt");
    let write = payload(
        &sb,
        "write_to_file",
        &json!({ "TargetFile": file.to_string_lossy(), "CodeContent": "x\n" }),
    );
    assert_eq!(
        guard(&sb, &write),
        (Some(OK), json!({ "decision": "allow" }))
    );

    let review = payload(
        &sb,
        "manage_task",
        &json!({ "Action": "send_input", "TaskId": "t", "Input": "ls\n" }),
    );
    let (code, reply) = guard(&sb, &review);
    assert_eq!(code, Some(OK), "{reply}");
    assert_eq!(reply["decision"], "force_ask", "{reply}");

    // A call no rule matches: `decision` is required, so OpenMoat answers
    // `allow`, documented as deferring to the default policy. An ungoverned
    // tool likewise.
    if !cfg!(windows) {
        let defer = payload(
            &sb,
            "run_command",
            &json!({ "CommandLine": "npm install left-pad" }),
        );
        assert_eq!(
            guard(&sb, &defer),
            (Some(OK), json!({ "decision": "allow" }))
        );
    }
    let tasks = payload(&sb, "manage_task", &json!({ "Action": "list" }));
    assert_eq!(
        guard(&sb, &tasks),
        (Some(OK), json!({ "decision": "allow" }))
    );
}

#[test]
fn malformed_arguments_are_denied() {
    let sb = Sandbox::installed(&[DIR]);
    let (code, reply) = guard(&sb, &fixture("antigravity-cli/view_file-malformed.json"));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");
    assert!(
        reply["reason"].to_string().contains("AbsolutePath"),
        "{reply}"
    );
}

#[test]
fn a_later_agent_or_a_scheduled_prompt_needs_review() {
    let sb = Sandbox::installed(&[DIR]);
    for (tool, args) in [
        (
            "schedule",
            json!({ "Prompt": "later", "DurationSeconds": 60 }),
        ),
        (
            "define_subagent",
            json!({ "name": "x", "system_prompt": "y" }),
        ),
        (
            "invoke_subagent",
            json!({ "Subagents": [{ "Prompt": "go" }] }),
        ),
    ] {
        let (code, reply) = guard(&sb, &payload(&sb, tool, &args));
        assert_eq!(code, Some(OK), "{tool}: {reply}");
        assert_eq!(reply["decision"], "force_ask", "{tool}: {reply}");
    }
}

/// `enabled: false` under OpenMoat's own entry never runs the hook: not
/// protected, and the lock catches the edit as any other. `init` turns it on.
#[test]
fn a_switched_off_entry_is_not_protected_and_init_turns_it_back_on() {
    let sb = Sandbox::installed(&[DIR]);
    let mut root: Value =
        serde_json::from_str(&fs::read_to_string(hook_file(&sb)).unwrap()).unwrap();
    root["openmoat"]["enabled"] = json!(false);
    fs::write(hook_file(&sb), root.to_string()).unwrap();
    let agent = status(&sb);
    assert_eq!(agent["level"], "not-protected", "{agent}");
    assert_eq!(agent["reason"], "hook turned off in its entry", "{agent}");

    let (code, reply) = guard(
        &sb,
        &payload(&sb, "list_dir", &json!({ "DirectoryPath": "/p" })),
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-integrity"),
        "{reply}"
    );

    let init = sb.moat_as_person(&["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    let root: Value = serde_json::from_str(&fs::read_to_string(hook_file(&sb)).unwrap()).unwrap();
    assert_eq!(root["openmoat"]["enabled"], true, "{root}");
}

/// A project's `.agents/hooks.json` loads from the repository: `status` warns
/// about what it adds and an entry that turns OpenMoat's hook off, and the
/// agent cannot write one.
#[test]
fn a_project_hook_file_is_warned_about_and_cannot_be_written() {
    let sb = Sandbox::installed(&[DIR]);
    let project = sb.project();
    let dir = project.join(".agents");
    fs::create_dir_all(&dir).unwrap();
    let theirs = json!({ "openmoat": { "enabled": false }, "lint": { "PreToolUse": [] } });
    fs::write(dir.join("hooks.json"), theirs.to_string()).unwrap();
    let mut cmd = sb.command();
    cmd.current_dir(&project)
        .args(["status", "--format", "json"]);
    let doc = parse(&crate::common::output(&mut cmd, None));
    let warnings = doc["project_settings"].to_string();
    assert!(warnings.contains("`openmoat.enabled`"), "{warnings}");
    assert!(warnings.contains("`lint` adds a hook"), "{warnings}");

    let write = payload(
        &sb,
        "write_to_file",
        &json!({ "TargetFile": dir.join("hooks.json").to_string_lossy(), "CodeContent": "{}" }),
    );
    let (code, reply) = guard(&sb, &write);
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-self"),
        "{reply}"
    );
}

/// A saved `toolPermission: always-proceed` approves requests unseen: a review
/// is sent as a deny that says how to approve it.
#[test]
fn a_review_under_always_proceed_is_a_deny() {
    let sb = Sandbox::installed(&[DIR]);
    fs::write(
        sb.home.join(DIR).join("settings.json"),
        r#"{"toolPermission": "always-proceed"}"#,
    )
    .unwrap();
    let review = payload(
        &sb,
        "manage_task",
        &json!({ "Action": "send_input", "TaskId": "t", "Input": "ls\n" }),
    );
    let (code, reply) = guard(&sb, &review);
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny", "{reply}");
    assert!(
        reply["reason"].to_string().contains("openmoat allow"),
        "{reply}"
    );
}

#[test]
fn an_mcp_tool_change_holds_back_its_calls() {
    let sb = Sandbox::bare(&[DIR]);
    fs::create_dir_all(hook_file(&sb).parent().unwrap()).unwrap();
    let mcp = hook_file(&sb).with_file_name("mcp_config.json");
    fs::write(&mcp, r#"{"mcpServers":{"gh":{"command":"npx"}}}"#).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let call = payload(
        &sb,
        "call_mcp_tool",
        &json!({ "ServerName": "gh", "ToolName": "issues", "Arguments": {} }),
    );
    let (code, reply) = guard(&sb, &call);
    assert_eq!(code, Some(OK), "{reply}");
    fs::write(&mcp, r#"{"mcpServers":{"gh":{"command":"sh"}}}"#).unwrap();
    let (code, reply) = guard(&sb, &call);
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("mcp-server-changed"),
        "{reply}"
    );
}

#[test]
fn uninstall_gives_the_file_back() {
    let sb = Sandbox::bare(&[DIR]);
    fs::create_dir_all(hook_file(&sb).parent().unwrap()).unwrap();
    fs::write(hook_file(&sb), ORIGINAL).unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));
    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let root: Value = serde_json::from_str(&fs::read_to_string(hook_file(&sb)).unwrap()).unwrap();
    assert_eq!(root, serde_json::from_str::<Value>(ORIGINAL).unwrap());
}
