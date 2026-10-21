//! GitHub Copilot CLI end to end: `init` writes a hook file of OpenMoat's own
//! into `~/.copilot/hooks/`, `guard --host copilot-cli` answers in Copilot's
//! `permissionDecision` format, the lock pins the file, and `uninstall` takes
//! it away again.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".copilot"])
}

fn hook_file(sb: &Sandbox) -> std::path::PathBuf {
    sb.home.join(".copilot/hooks/openmoat.json")
}

/// A camelCase `preToolUse` payload, `toolArgs` as the JSON string Copilot sends.
fn payload(cwd: &Path, tool: &str, args: &Value) -> String {
    json!({
        "sessionId": "cp-1", "timestamp": 1_792_540_800_000_u64,
        "cwd": cwd.to_string_lossy(), "toolName": tool, "toolArgs": args.to_string(),
    })
    .to_string()
}

fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, String) {
    let out = sb.guard("copilot-cli", payload);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn decision(stdout: &str) -> Value {
    serde_json::from_str(stdout.trim()).unwrap_or(Value::Null)
}

#[test]
fn init_writes_one_hook_entry_for_every_tool_and_is_idempotent() {
    let sb = sandbox();
    let first = fs::read_to_string(hook_file(&sb)).unwrap();
    let root: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(root["version"], 1);
    let entries = root["hooks"]["preToolUse"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{root}");
    let entry = &entries[0];
    assert!(entry.get("matcher").is_none(), "every tool: {entry}");
    assert_eq!(entry["timeoutSec"], 600);
    for shell in ["bash", "powershell"] {
        assert!(
            entry[shell]
                .as_str()
                .unwrap()
                .ends_with(" guard --host copilot-cli"),
            "{entry}"
        );
    }
    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(OK), "{}", text(&again));
    assert_eq!(fs::read_to_string(hook_file(&sb)).unwrap(), first);
    let status = text(&sb.moat(&["status"]));
    assert!(status.contains("GitHub Copilot CLI"), "{status}");
    let doctor = text(&sb.moat(&["doctor"]));
    assert!(doctor.contains("GitHub Copilot CLI"), "{doctor}");
    assert!(doctor.contains("hook only"), "{doctor}");
}

#[test]
fn a_secret_read_is_denied_and_project_work_is_allowed() {
    let sb = sandbox();
    let project = sb.project();
    let secret = sb.home.join(".aws").join("credentials");
    let (code, out) = guard(
        &sb,
        &payload(
            &project,
            "view",
            &json!({ "path": secret.to_string_lossy() }),
        ),
    );
    assert_eq!(code, Some(DENY), "{out}");
    let doc = decision(&out);
    assert_eq!(doc["permissionDecision"], "deny", "{out}");
    assert!(
        doc["permissionDecisionReason"]
            .to_string()
            .contains("secrets-paths"),
        "{out}"
    );

    let (code, out) = guard(
        &sb,
        &payload(&project, "bash", &json!({ "command": "cargo test" })),
    );
    assert_eq!(code, Some(OK), "{out}");
    assert_eq!(decision(&out)["permissionDecision"], "allow", "{out}");

    // A tool OpenMoat does not govern is left to Copilot: no output, exit 0.
    let (code, out) = guard(
        &sb,
        &payload(&project, "report_intent", &json!({ "intent": "x" })),
    );
    assert_eq!((code, out.trim()), (Some(OK), ""), "{out}");
}

/// Copilot's hook file and its settings, which `disableAllHooks` would turn
/// off, are `kernel-self`'s; an MCP tool reading a key is checked by its path.
#[test]
fn writes_that_would_switch_the_hook_off_are_denied() {
    let sb = sandbox();
    let project = sb.project();
    for path in [
        hook_file(&sb),
        sb.home.join(".copilot/settings.json"),
        project.join(".github/copilot/settings.local.json"),
    ] {
        let args = json!({ "path": path.to_string_lossy(), "file_text": "{}" });
        let (code, out) = guard(&sb, &payload(&project, "create", &args));
        assert_eq!(code, Some(DENY), "{}: {out}", path.display());
        assert!(out.contains("kernel-self"), "{}: {out}", path.display());
    }
    let key = sb.home.join(".ssh").join("id_ed25519");
    let args = json!({ "path": key.to_string_lossy() });
    let (code, out) = guard(&sb, &payload(&project, "filesystem-read_file", &args));
    assert_eq!(code, Some(DENY), "{out}");
    assert!(out.contains("secrets-paths"), "{out}");
}

#[test]
fn arguments_that_do_not_parse_fail_closed() {
    let sb = sandbox();
    let broken = json!({
        "sessionId": "cp-1", "cwd": sb.project().to_string_lossy(),
        "toolName": "bash", "toolArgs": "{\"command\": ",
    })
    .to_string();
    let (code, out) = guard(&sb, &broken);
    assert_eq!(code, Some(DENY), "{out}");
    assert_eq!(decision(&out)["permissionDecision"], "deny", "{out}");
    assert!(out.contains("kernel-error"), "{out}");
}

/// The lock pins the hook file: once it is edited on disk, every call is
/// denied until a person re-pins.
#[test]
fn an_edited_hook_file_is_kernel_integrity() {
    let sb = sandbox();
    let path = hook_file(&sb);
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("\"timeoutSec\": 600", "\"timeoutSec\": 1");
    fs::write(&path, edited).unwrap();
    let project = sb.project();
    let (code, out) = guard(&sb, &payload(&project, "bash", &json!({ "command": "ls" })));
    assert_eq!(code, Some(DENY), "{out}");
    assert!(out.contains("kernel-integrity"), "{out}");
}

#[test]
fn uninstall_deletes_the_hook_file_init_created() {
    let sb = sandbox();
    assert!(hook_file(&sb).is_file());
    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!hook_file(&sb).exists(), "{}", text(&out));
    assert!(sb.home.join(".copilot").is_dir(), "the directory stays");
}

/// The servers in `~/.copilot/mcp-config.json` are pinned at `init`; a changed
/// one holds back the tool calls named `<server>-…` until a person accepts it,
/// and the others run.
#[test]
fn a_changed_mcp_server_holds_back_its_tools_until_accepted() {
    let sb = Sandbox::bare(&[".copilot"]);
    let config = sb.home.join(".copilot/mcp-config.json");
    let servers = |gh: &str| {
        json!({ "mcpServers": {
            "gh": { "type": "local", "command": gh, "tools": ["*"] },
            "db": { "type": "http", "url": "https://db.example/mcp" },
        }})
        .to_string()
    };
    fs::write(&config, servers("npx")).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("2 definitions pinned"),
        "{}",
        text(&out)
    );
    let project = sb.project();
    let call = |tool: &str| guard(&sb, &payload(&project, tool, &json!({ "q": "x" })));
    assert_eq!(call("gh-search").0, Some(OK));

    fs::write(&config, servers("sh")).unwrap();
    let (code, out) = call("gh-search");
    assert_eq!(code, Some(DENY), "{out}");
    assert!(out.contains("mcp-server-changed"), "{out}");
    assert_eq!(call("db-query").0, Some(OK), "other servers run");

    let accept = sb.moat_approving(&["mcp", "accept", "gh"]);
    assert_eq!(accept.status.code(), Some(OK), "{}", text(&accept));
    assert_eq!(call("gh-search").0, Some(OK));
}

/// `disableAllHooks` in Copilot's own `settings.json` skips OpenMoat's hook
/// file: the hook is installed and pinned, yet the agent is not protected.
#[test]
fn disable_all_hooks_in_the_user_settings_is_not_protected() {
    let sb = sandbox();
    let settings = sb.home.join(".copilot/settings.json");
    fs::write(&settings, r#"{"disableAllHooks": true}"#).unwrap();
    let status = sb.moat(&["status", "--format", "json"]);
    let report: Value = serde_json::from_slice(&status.stdout).unwrap();
    let copilot = report["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["host"] == "copilot-cli")
        .unwrap();
    assert_eq!(copilot["level"], "not-protected", "{copilot}");
    assert!(
        copilot["reason"].to_string().contains("disableAllHooks"),
        "{copilot}"
    );
    fs::write(&settings, r#"{"disableAllHooks": false}"#).unwrap();
    let doctor = text(&sb.moat(&["doctor"]));
    assert!(doctor.contains("hook only"), "{doctor}");
}
