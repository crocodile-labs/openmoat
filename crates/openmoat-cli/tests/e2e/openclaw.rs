//! OpenClaw integration end to end: `init` writes OpenMoat's plugin and its
//! `openclaw.json` entries, `guard --host openclaw` answers in the plugin's
//! format, and `uninstall` gives the file back.
//!
//! The payloads follow the documented `before_tool_call` event and context
//! (`tests/fixtures/hosts/openclaw/README.md`); none is captured from a Gateway.

use std::fs;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as parse, output, stdout, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".openclaw"])
}

/// A `before_tool_call` payload for `tool` with `params`, in the project.
pub(crate) fn payload(sb: &Sandbox, tool: &str, params: &Value) -> String {
    let project = sb.project();
    json!({
        "hook_event_name": "before_tool_call",
        "toolName": tool, "params": params,
        "toolCallId": "call-1", "runId": "run-1",
        "sessionId": "sess-1", "sessionKey": "agent:main:main", "agentId": "main",
        "cwd": project.to_string_lossy(),
        "configPath": sb.home.join(".openclaw/openclaw.json").to_string_lossy(),
        "platform": "linux",
    })
    .to_string()
}

/// The exit code and the reply; `Value::Null` when the hook printed nothing.
fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("openclaw", payload);
    let reply = if stdout(&out).trim().is_empty() {
        Value::Null
    } else {
        parse(&out)
    };
    (out.status.code(), reply)
}

#[test]
fn init_writes_the_plugin_and_its_entries_once() {
    let sb = sandbox();
    let config: Value =
        serde_json::from_str(&fs::read_to_string(sb.home.join(".openclaw/openclaw.json")).unwrap())
            .unwrap();
    let plugin = sb.home.join(".openclaw/openmoat/openmoat.mjs");
    let paths = config["plugins"]["load"]["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 1, "{config}");
    assert!(
        paths[0]
            .as_str()
            .unwrap()
            .ends_with("openmoat/openmoat.mjs")
    );
    assert_eq!(
        config["plugins"]["entries"]["openmoat"],
        json!({"enabled": true, "hooks": {"timeouts": {"before_tool_call": 60000}}})
    );
    let source = fs::read_to_string(&plugin).unwrap();
    let binary = serde_json::to_string(env!("CARGO_BIN_EXE_openmoat")).unwrap();
    assert!(
        source.contains(&format!("const MOAT = {binary};")),
        "{source}"
    );
}

#[test]
fn an_edit_of_openclaws_configuration_is_denied() {
    let sb = sandbox();
    let config = sb.home.join(".openclaw/openclaw.json");
    let edit = json!({"path": config, "edits": [{"oldText": "true", "newText": "false"}]});
    let (code, reply) = guard(&sb, &payload(&sb, "edit", &edit));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-self"),
        "{reply}"
    );

    let disable = json!({"action": "disable", "pluginId": "openmoat"});
    let (code, reply) = guard(&sb, &payload(&sb, "plugins", &disable));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-self"),
        "{reply}"
    );

    let poison =
        json!({"command": "node build.js", "env": {"NODE_OPTIONS": "--require /tmp/x.js"}});
    let (code, reply) = guard(&sb, &payload(&sb, "exec", &poison));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("env-poison"),
        "{reply}"
    );
}

#[test]
fn a_cron_job_is_denied_and_listing_jobs_is_left_to_openclaw() {
    let sb = sandbox();
    let add = json!({"action": "add", "job": {"schedule": {"kind": "cron", "expr": "0 3 * * *"},
        "payload": {"kind": "agentTurn", "message": "sync"}}});
    let (code, reply) = guard(&sb, &payload(&sb, "cron", &add));
    assert_eq!(code, Some(DENY), "{reply}");
    assert_eq!(reply["decision"], "deny", "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-self"),
        "{reply}"
    );
    let (code, reply) = guard(&sb, &payload(&sb, "cron", &json!({"action": "list"})));
    assert_eq!((code, reply), (Some(OK), Value::Null));
}

#[test]
fn openclaw_config_path_is_followed_and_protected() {
    let sb = Sandbox::bare(&[".openclaw"]);
    let config = sb.home.join("etc/main.json5");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "{ gateway: { port: 18789 } }\n").unwrap();
    let out = output(
        sb.command()
            .args(["init", "--yes", "--hosts", "openclaw"])
            .env("OPENCLAW_CONFIG_PATH", "~/etc/main.json5"),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let written: Value = serde_json::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(written["gateway"]["port"], 18789);
    assert!(
        written["plugins"]["entries"]["openmoat"].is_object(),
        "{written}"
    );
    assert!(sb.home.join(".openclaw/openmoat/openmoat.mjs").is_file());
    assert!(!sb.home.join(".openclaw/openclaw.json").exists());

    // Later commands follow the record, without the variable.
    let edit = json!({"path": config, "content": "{}"});
    let (code, reply) = guard(&sb, &payload(&sb, "write", &edit));
    assert_eq!(code, Some(DENY), "{reply}");
    assert!(
        reply["reason"].to_string().contains("kernel-self"),
        "{reply}"
    );
    let doctor = text(&sb.moat(&["doctor"]));
    assert!(doctor.contains("main.json5"), "{doctor}");
}

#[test]
fn a_configuration_with_comments_is_not_rewritten() {
    let sb = Sandbox::bare(&[".openclaw"]);
    let config = sb.home.join(".openclaw/openclaw.json");
    let original = "// my gateway\n{ gateway: { port: 18789 } }\n";
    fs::write(&config, original).unwrap();
    let out = sb.moat(&["init", "--yes", "--hosts", "openclaw"]);
    assert!(text(&out).contains("comments"), "{}", text(&out));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    assert!(!sb.home.join(".openclaw/openmoat").exists());
}
