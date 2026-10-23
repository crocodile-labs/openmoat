//! GitHub Copilot CLI end to end: `init` writes a hook file of OpenMoat's own
//! into `~/.copilot/hooks/`, `guard --host copilot-cli` answers in Copilot's
//! `permissionDecision` format, the lock pins the file, and `uninstall` takes
//! it away again.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::common::{DENY, Sandbox, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".copilot"])
}

fn hook_file(sb: &Sandbox) -> std::path::PathBuf {
    sb.home.join(".copilot/hooks/openmoat.json")
}

/// A camelCase `preToolUse` payload, `toolArgs` as the JSON string Copilot sends.
pub(crate) fn payload(cwd: &Path, tool: &str, args: &Value) -> String {
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

#[test]
fn init_writes_one_hook_entry_for_every_tool() {
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

/// `disableAllHooks: true` turns the hook off (the shared suite,
/// `hosts/settings.rs`); `false` leaves it on.
#[test]
fn disable_all_hooks_false_is_hook_only() {
    let sb = sandbox();
    let settings = sb.home.join(".copilot/settings.json");
    fs::write(&settings, r#"{"disableAllHooks": false}"#).unwrap();
    let doctor = text(&sb.moat(&["doctor"]));
    assert!(doctor.contains("hook only"), "{doctor}");
}
