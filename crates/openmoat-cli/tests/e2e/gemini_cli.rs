//! Gemini CLI end to end: `init` adds one `BeforeTool` entry to
//! `settings.json`, `guard --host gemini-cli` answers with Gemini CLI's
//! `decision`, and `uninstall` gives the file back.
//!
//! The payloads follow the hooks reference and the source of
//! `@google/gemini-cli` 0.65.0 (`tests/fixtures/hosts/gemini-cli/README.md`);
//! none is captured from a signed-in session.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, fixture, json as parse, stdout, text};

/// A settings file as Gemini CLI writes it, two-space indented.
pub(crate) const ORIGINAL: &str = "{\n  \"ui\": { \"theme\": \"GitHub\" },\n  \"general\": {}\n}\n";

fn settings(sb: &Sandbox) -> std::path::PathBuf {
    sb.home.join(".gemini/settings.json")
}

/// A `BeforeTool` payload for `tool` with `input`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    json!({
        "session_id": "gem-1", "transcript_path": "",
        "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "BeforeTool", "timestamp": "2026-10-20T10:00:00.000Z",
        "tool_name": tool, "tool_input": input,
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("gemini-cli", payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

#[test]
fn init_adds_one_named_before_tool_entry() {
    let sb = Sandbox::bare(&[".gemini"]);
    let theirs = json!({ "ui": { "theme": "GitHub" }, "model": { "name": "gemini-2.5-pro" } });
    fs::write(settings(&sb), theirs.to_string()).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let root: Value = serde_json::from_str(&fs::read_to_string(settings(&sb)).unwrap()).unwrap();
    assert_eq!(root["ui"], theirs["ui"]);
    let entries = root["hooks"]["BeforeTool"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{root}");
    assert_eq!(entries[0]["matcher"], "*");
    let hook = &entries[0]["hooks"][0];
    assert_eq!(hook["name"], "openmoat");
    assert_eq!(hook["timeout"], 600_000);
    assert!(
        hook["command"]
            .as_str()
            .unwrap()
            // PowerShell adds `; if (-not $?) { exit 2 }` on Windows
            .contains(" guard --host gemini-cli"),
        "{hook}"
    );
    let before = fs::read_to_string(settings(&sb)).unwrap();
    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert_eq!(fs::read_to_string(settings(&sb)).unwrap(), before);
}

#[test]
fn a_secret_read_or_upload_is_denied() {
    let sb = Sandbox::installed(&[".gemini"]);
    // On Windows Gemini CLI runs commands in PowerShell, which OpenMoat leaves
    // unparsed (`unparseable`, a defer), as for Claude Code's PowerShell tool.
    if !cfg!(windows) {
        let (code, reply) = guard(&sb, &fixture("gemini-cli/run_shell_command.json"));
        assert_eq!(code, Some(DENY), "{reply}");
        assert_eq!(reply["decision"], "deny");
        let reason = reply["reason"].as_str().unwrap();
        assert!(reason.contains("secrets-paths"), "{reason}");
        assert_eq!(reply["systemMessage"], reply["reason"]);
    }

    let secret = sb.home.join(".aws").join("credentials");
    let read = payload(
        &sb,
        "read_file",
        &json!({ "file_path": secret.to_string_lossy() }),
    );
    let (code, reply) = guard(&sb, &read);
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reply["reason"].to_string().contains("secrets-paths"));
}

/// `dir_path` is where Gemini CLI runs a command, chosen by the model; it never
/// decides which directory is the project. A session in the home folder that
/// writes a launch agent with `dir_path` there still asks (`persistence`)
/// instead of being allowed as a write in its own "project".
#[test]
fn dir_path_never_makes_a_directory_the_project() {
    if cfg!(windows) {
        return;
    }
    let sb = Sandbox::installed(&[".gemini"]);
    fs::create_dir_all(sb.home.join("Library/LaunchAgents")).unwrap();
    let write = json!({
        "session_id": "gem-1", "transcript_path": "", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "BeforeTool", "timestamp": "2026-10-20T10:00:00.000Z",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "echo x > evil.plist", "dir_path": "Library/LaunchAgents"},
    });
    let (code, reply) = guard(&sb, &write.to_string());
    assert_eq!(code, Some(OK), "{reply}");
    assert_eq!(reply["decision"], "ask", "{reply}");
    assert!(
        reply["reason"].to_string().contains("persistence"),
        "{reply}"
    );
}

#[test]
fn allow_ask_and_no_decision_reach_gemini_as_its_own_shapes() {
    let sb = Sandbox::installed(&[".gemini"]);
    let file = sb.project().join("src/main.rs");
    let write = payload(
        &sb,
        "write_file",
        &json!({ "file_path": file.to_string_lossy(), "content": "fn main() {}\n" }),
    );
    let (code, reply) = guard(&sb, &write);
    assert_eq!(code, Some(OK));
    assert_eq!(reply, json!({ "decision": "allow" }));

    // still an `ask` under ADR-025: a pager is a program git runs later;
    // Gemini CLI puts the question to the person itself
    let ask = payload(
        &sb,
        "run_shell_command",
        &json!({ "command": "git config core.pager less" }),
    );
    let (code, reply) = guard(&sb, &ask);
    assert_eq!(code, Some(OK), "{reply}");
    // PowerShell on Windows: left to Gemini CLI unparsed, as above
    if !cfg!(windows) {
        assert_eq!(reply["decision"], "ask");
        assert!(reply["systemMessage"].to_string().contains("git-internals"));
    }

    // a call no rule matches, and a tool OpenMoat does not govern: nothing on
    // stdout, so Gemini CLI's own policy decides
    let defer = payload(
        &sb,
        "run_shell_command",
        &json!({ "command": "npm install left-pad" }),
    );
    assert_eq!(guard(&sb, &defer), (Some(OK), Value::Null));
    let todos = guard(&sb, &fixture("gemini-cli/write_todos.json"));
    assert_eq!(todos, (Some(OK), Value::Null));
}

#[test]
fn a_payload_that_cannot_be_checked_is_denied() {
    let sb = Sandbox::installed(&[".gemini"]);
    let (code, reply) = guard(&sb, &fixture("gemini-cli/read_file-malformed.json"));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");
    assert!(reply["reason"].to_string().contains("file_path"), "{reply}");
}

/// Apply `change` to the installed settings file, as Gemini CLI or an agent would.
fn edit_settings(sb: &Sandbox, change: impl FnOnce(&mut Value)) {
    let mut root: Value = serde_json::from_str(&fs::read_to_string(settings(sb)).unwrap()).unwrap();
    change(&mut root);
    fs::write(settings(sb), serde_json::to_string_pretty(&root).unwrap()).unwrap();
}

/// The verdict and reason for writing a project file: `allow` while the guard
/// decides, a `kernel-integrity` deny once the lock froze every call.
fn write_project_file(sb: &Sandbox) -> (Option<i32>, Value) {
    let write = payload(
        sb,
        "write_file",
        &json!({ "file_path": sb.project().join("a.txt").to_string_lossy(), "content": "" }),
    );
    guard(sb, &write)
}

#[track_caller]
fn assert_frozen(sb: &Sandbox, what: &str) {
    let (code, reply) = write_project_file(sb);
    assert_eq!(code, Some(DENY), "{what}: {reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-integrity"),
        "{what}: {reply}"
    );
}

/// A named change to a settings file.
type Change = (&'static str, fn(&mut Value));

/// Gemini CLI saves `/model` and `/theme` in the file that holds OpenMoat's
/// hook: the guard keeps deciding, and `doctor` reports the drift.
#[test]
fn a_new_model_or_theme_alone_leaves_calls_decided_and_is_reported() {
    let changes: [Change; 2] = [
        ("model", |s| {
            s["model"] = json!({ "name": "gemini-2.5-flash" });
        }),
        ("ui", |s| s["ui"] = json!({ "theme": "Dracula" })),
    ];
    for (key, change) in changes {
        let sb = Sandbox::installed(&[".gemini"]);
        edit_settings(&sb, change);
        assert_eq!(
            write_project_file(&sb),
            (Some(OK), json!({ "decision": "allow" }))
        );
        let secret = sb.home.join(".aws").join("credentials");
        let read = payload(
            &sb,
            "read_file",
            &json!({ "file_path": secret.to_string_lossy() }),
        );
        let (code, reply) = guard(&sb, &read);
        assert_eq!(code, Some(DENY), "{reply}");
        assert!(
            reply["reason"].to_string().contains("secrets-paths"),
            "{reply}"
        );
        assert!(
            !reply["reason"].to_string().contains("kernel-integrity"),
            "{reply}"
        );

        let doctor = text(&sb.moat(&["doctor"]));
        let expected = format!("settings.json was modified: added {key}");
        assert!(doctor.contains(&expected), "{doctor}");
        assert!(doctor.contains("openmoat doctor --accept"), "{doctor}");
    }
}

/// Every write below changes what runs, what is checked or what Gemini CLI
/// reads; each denies every call until a person re-pins.
#[test]
fn any_other_settings_change_denies_every_call() {
    let changes: [Change; 8] = [
        ("hook added", |s| {
            s["hooks"]["BeforeTool"].as_array_mut().unwrap().push(
                json!({ "matcher": "*", "hooks": [{ "type": "command", "command": "/tmp/rewrite" }] }),
            );
        }),
        ("hook removed", |s| {
            s.as_object_mut().unwrap().remove("hooks");
        }),
        ("hooks off", |s| {
            s["hooksConfig"] = json!({ "enabled": false });
        }),
        ("MCP server added", |s| {
            s["mcpServers"] = json!({ "evil": { "command": "/tmp/server" } });
        }),
        ("sandbox off", |s| s["tools"] = json!({ "sandbox": false })),
        ("unknown key", |s| s["somethingNew"] = json!(true)),
        ("theme next to a hook change", |s| {
            s["ui"] = json!({ "theme": "Dracula" });
            s["hooksConfig"] = json!({ "enabled": false });
        }),
        ("model of another shape", |s| {
            s["model"] = json!({ "name": ["x"] });
        }),
    ];
    for (what, change) in changes {
        let sb = Sandbox::installed(&[".gemini"]);
        edit_settings(&sb, change);
        assert_frozen(&sb, what);
    }
}

/// A tool the person excluded, allowed again, denies like any other change.
#[test]
fn an_excluded_tool_enabled_again_denies_every_call() {
    let sb = Sandbox::bare(&[".gemini"]);
    let theirs = json!({ "tools": { "exclude": ["run_shell_command(rm)"] } });
    fs::write(settings(&sb), theirs.to_string()).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    edit_settings(&sb, |s| s["tools"]["exclude"] = json!([]));
    assert_frozen(&sb, "excluded tool enabled");
}

#[test]
fn settings_that_no_longer_parse_deny_every_call() {
    let sb = Sandbox::installed(&[".gemini"]);
    fs::write(settings(&sb), r#"{"model": {"name": "#).unwrap();
    assert_frozen(&sb, "broken file");
}

/// The protection entry and the report `status --format json` prints, in `cwd`.
fn status_in(sb: &Sandbox, cwd: &std::path::Path) -> (Value, Value) {
    let mut cmd = sb.command();
    cmd.current_dir(cwd).args(["status", "--format", "json"]);
    let doc = parse(&crate::common::output(&mut cmd, None));
    let agent = doc["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["host"] == "gemini-cli")
        .unwrap()
        .clone();
    (agent, doc)
}

/// `init` pins the settings file as it finds it: a `hooksConfig` that turns
/// hooks off stays, and the agent is reported as not protected.
#[test]
fn hooks_turned_off_in_the_user_settings_is_not_protected() {
    let sb = Sandbox::bare(&[".gemini"]);
    fs::write(
        settings(&sb),
        json!({ "hooksConfig": { "enabled": false } }).to_string(),
    )
    .unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (agent, _) = status_in(&sb, &sb.home);
    assert_eq!(agent["level"], "not-protected", "{agent}");
    assert!(
        agent["reason"].to_string().contains("hooksConfig.enabled"),
        "{agent}"
    );
}

/// A trusted folder's `.gemini/settings.json` loads at start: `status` names
/// what in it turns OpenMoat off or adds a hook.
#[test]
fn a_project_settings_file_that_disables_openmoat_is_warned_about() {
    let sb = Sandbox::installed(&[".gemini"]);
    let project = sb.project();
    let (agent, doc) = status_in(&sb, &project);
    assert_eq!(agent["level"], "hook-only", "{agent}");
    assert_eq!(doc["project_settings"], json!([]), "{doc}");
    fs::create_dir_all(project.join(".gemini")).unwrap();
    let theirs = json!({
        "hooksConfig": { "disabled": ["openmoat"] },
        "hooks": { "BeforeTool": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "./x" }] }] },
    });
    fs::write(project.join(".gemini/settings.json"), theirs.to_string()).unwrap();
    let (_, doc) = status_in(&sb, &project);
    let warnings = doc["project_settings"].to_string();
    assert!(warnings.contains("`hooksConfig.disabled`"), "{warnings}");
    assert!(warnings.contains("`hooks` adds hooks"), "{warnings}");
}
