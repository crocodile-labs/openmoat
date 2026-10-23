//! pi integration end to end: `init` writes OpenMoat's extension into pi's
//! agent directory and pins it, `guard --host pi` answers in the extension's
//! format, and `uninstall` takes the extension away.
//!
//! The payloads follow the documented `tool_call` event and context
//! (`tests/fixtures/hosts/pi/README.md`); none is captured from pi.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, output, stdout, text};

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
fn writes_to_pis_own_files_are_denied() {
    let sb = sandbox();
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

/// In pi's terminal UI an `ask` is a dialog (the shared suite); without
/// one it is a deny that says how to approve.
#[test]
fn an_ask_without_the_ui_is_a_deny() {
    let sb = Sandbox::installed_asking(&[AGENT_DIR]);
    let outside = json!({"path": sb.home.join("notes/todo.txt")});
    let (code, reply) = guard(&sb, &payload_ui(&sb, "read", &outside, false));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny", "{reply}");
    assert!(reason(&reply).contains("openmoat allow --last"), "{reply}");
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

/// A project's settings and extensions are warned about; pi's own settings
/// turning the extension off are the shared suite's (`hosts/settings.rs`).
#[test]
fn project_settings_that_turn_the_extension_off_are_reported() {
    let sb = sandbox();
    let project = sb.project();
    let (agent, _) = agent_status(&sb, &project, "pi");
    assert_eq!(agent["level"], "hook-only", "{agent}");

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
