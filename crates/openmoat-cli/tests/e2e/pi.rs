//! pi integration end to end: `init` writes OpenMoat's extension into pi's
//! agent directory and pins it, `guard --host pi` answers in the extension's
//! format, and `uninstall` takes the extension away.
//!
//! The payloads follow the documented `tool_call` event and context
//! (`tests/fixtures/hosts/pi/README.md`); none is captured from pi.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, fixture, json as parse, output, stdout, text};

const AGENT_DIR: &str = ".pi/agent";

fn sandbox() -> Sandbox {
    Sandbox::installed(&[AGENT_DIR])
}

/// A `tool_call` payload for `tool` with `input`, in the project, from pi's
/// terminal UI when `ui`.
fn payload_ui(sb: &Sandbox, tool: &str, input: &Value, ui: bool) -> String {
    json!({
        "hook_event_name": "tool_call",
        "toolName": tool, "input": input, "toolCallId": "call-1",
        "sessionId": "sess-1", "cwd": sb.project().to_string_lossy(),
        "hasUI": ui, "platform": "linux",
    })
    .to_string()
}

pub(crate) fn payload(sb: &Sandbox, tool: &str, input: &Value) -> String {
    payload_ui(sb, tool, input, true)
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("pi", payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

fn reason(reply: &Value) -> String {
    reply["reason"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn init_writes_the_extension_once() {
    let sb = sandbox();
    let extension = sb.home.join(AGENT_DIR).join("extensions/openmoat.js");
    let source = fs::read_to_string(&extension).unwrap();
    let binary = serde_json::to_string(env!("CARGO_BIN_EXE_openmoat")).unwrap();
    assert!(
        source.contains(&format!("const MOAT = {binary};")),
        "{source}"
    );
}

#[test]
fn a_secret_read_and_writes_to_pis_own_files_are_denied() {
    let sb = sandbox();
    let read = json!({"path": "@~/.ssh/id_ed25519"});
    let (code, reply) = guard(&sb, &payload(&sb, "read", &read));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");
    assert!(reason(&reply).contains("secrets-paths"), "{reply}");

    let agent = sb.home.join(AGENT_DIR);
    for (tool, input) in [
        (
            "edit",
            json!({"path": agent.join("extensions/openmoat.js"),
                "edits": [{"oldText": "guard", "newText": "noop"}]}),
        ),
        (
            "write",
            json!({"path": agent.join("settings.json"),
                "content": "{\"extensions\":[\"-extensions/openmoat.js\"]}"}),
        ),
        ("bash", json!({"command": "rm -rf ~/.pi/agent/extensions"})),
    ] {
        let (code, reply) = guard(&sb, &payload(&sb, tool, &input));
        assert_eq!(code, Some(DENY), "{tool}: {reply}");
        assert!(reason(&reply).contains("kernel-self"), "{tool}: {reply}");
    }
}

#[test]
fn a_safe_command_is_allowed_and_an_unknown_tool_is_left_to_pi() {
    let sb = sandbox();
    let (code, reply) = guard(
        &sb,
        &payload(&sb, "bash", &json!({"command": "git status"})),
    );
    assert_eq!(code, Some(OK), "{reply}");
    assert_eq!(reply["decision"], "allow", "{reply}");

    let (code, reply) = guard(&sb, &payload(&sb, "codemode", &json!({"code": "1"})));
    assert_eq!((code, reply), (Some(OK), Value::Null));
}

#[test]
fn an_ask_is_a_dialog_in_the_ui_and_a_deny_without_one() {
    let sb = Sandbox::installed_asking(&[AGENT_DIR]);
    let outside = json!({"path": sb.home.join("notes/todo.txt")});
    let (code, reply) = guard(&sb, &payload(&sb, "read", &outside));
    assert_eq!(code, Some(OK), "{reply}");
    assert_eq!(reply["decision"], "ask", "{reply}");

    let (code, reply) = guard(&sb, &payload_ui(&sb, "read", &outside, false));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny", "{reply}");
    assert!(reason(&reply).contains("openmoat allow --last"), "{reply}");
}

#[test]
fn malformed_input_and_other_events_are_denied() {
    let sb = sandbox();
    let (code, reply) = guard(&sb, &fixture("pi/read-malformed.json"));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");

    let (code, reply) = guard(
        &sb,
        r#"{"hook_event_name":"tool_result","toolName":"bash"}"#,
    );
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny");
}

#[test]
fn a_moved_agent_directory_is_followed_and_protected() {
    let sb = Sandbox::bare(&[]);
    let moved = sb.home.join("pi-home");
    fs::create_dir_all(&moved).unwrap();
    let out = output(
        sb.command()
            .args(["init", "--yes", "--hosts", "pi"])
            .env("PI_CODING_AGENT_DIR", &moved),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let extension = moved.join("extensions/openmoat.js");
    assert!(extension.is_file(), "{}", text(&out));
    assert!(!sb.home.join(AGENT_DIR).exists());

    // Later commands follow the record, without the variable.
    let write = json!({"path": extension, "content": "export default () => {}"});
    let (code, reply) = guard(&sb, &payload(&sb, "write", &write));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reason(&reply).contains("kernel-self"), "{reply}");
}

/// The protection entry `status --format json` prints for `host`, run in `cwd`.
fn agent_status(sb: &Sandbox, cwd: &std::path::Path, host: &str) -> (Value, Value) {
    let mut cmd = sb.command();
    cmd.current_dir(cwd).args(["status", "--format", "json"]);
    let doc = parse(&output(&mut cmd, None));
    let agent = doc["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["host"] == host)
        .unwrap()
        .clone();
    (agent, doc)
}

/// The servers in pi's `mcp.json` are pinned at `init`; a changed one holds
/// back its `mcp__<server>__…` tools, spelled as pi spells them.
#[test]
fn a_changed_mcp_server_in_the_agent_directory_is_held_back() {
    let sb = Sandbox::bare(&[AGENT_DIR]);
    let config = sb.home.join(AGENT_DIR).join("mcp.json");
    let servers = |command: &str| {
        json!({ "mcpServers": { "internal-tools": { "command": command } } }).to_string()
    };
    fs::write(&config, servers("npx")).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("1 definitions pinned"),
        "{}",
        text(&out)
    );
    let call = || guard(&sb, &payload(&sb, "mcp__internal_tools__run", &json!({})));
    assert_eq!(call().0, Some(OK));
    fs::write(&config, servers("sh")).unwrap();
    let (code, reply) = call();
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(reason(&reply).contains("mcp-server-changed"), "{reply}");
}

/// An `extensions` entry in pi's own settings that excludes OpenMoat's
/// extension leaves the hook pinned but never loaded; a project's settings
/// and extensions are warned about.
#[test]
fn settings_that_turn_the_extension_off_are_reported() {
    let sb = sandbox();
    let project = sb.project();
    let (agent, _) = agent_status(&sb, &project, "pi");
    assert_eq!(agent["level"], "hook-only", "{agent}");

    let settings = sb.home.join(AGENT_DIR).join("settings.json");
    fs::write(&settings, r#"{"extensions": ["-extensions/openmoat.js"]}"#).unwrap();
    let (agent, _) = agent_status(&sb, &project, "pi");
    assert_eq!(agent["level"], "not-protected", "{agent}");
    assert!(
        agent["reason"]
            .to_string()
            .contains("-extensions/openmoat.js"),
        "{agent}"
    );
    fs::remove_file(&settings).unwrap();

    fs::create_dir_all(project.join(".pi/extensions")).unwrap();
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"extensions": ["!*.js"]}"#,
    )
    .unwrap();
    fs::write(
        project.join(".pi/extensions/helper.ts"),
        "export default () => {}",
    )
    .unwrap();
    let (_, doc) = agent_status(&sb, &project, "pi");
    let warnings = doc["project_settings"].to_string();
    assert!(
        warnings.contains("`!*.js` turns OpenMoat's extension off"),
        "{warnings}"
    );
    assert!(
        warnings.contains("helper.ts: is an extension pi loads"),
        "{warnings}"
    );
}
