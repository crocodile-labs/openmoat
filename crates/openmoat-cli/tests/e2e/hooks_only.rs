//! `openmoat init --hooks-only --format json`: installs and pins only the
//! selected host hooks without touching agent sandboxes, MCP wrapping, or
//! unrelated hosts in `moat.lock`.

use std::path::Path;

use serde_json::Value;

use crate::common::{OK, Sandbox, text};

#[test]
fn hooks_only_dry_run_json_writes_nothing_and_plans_selected_host() {
    let sb = Sandbox::bare(&[".codex", ".claude"]);
    let config_toml = sb.home.join(".codex/config.toml");
    std::fs::write(&config_toml, "model = \"gpt-5\"\n").unwrap();

    let out = sb.moat(&[
        "init",
        "--hooks-only",
        "--dry-run",
        "--format",
        "json",
        "--hosts",
        "codex",
    ]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["dry_run"], true);
    assert_eq!(doc["hooks_only"], true);
    assert_eq!(doc["changed"], true);
    assert!(doc["lock_entries_count"].is_null());
    assert!(doc["binary_sha256"].as_str().is_some_and(|s| s.len() == 64));

    let hosts = doc["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["host"], "codex");
    assert_eq!(hosts[0]["outcome"], "installed");
    assert_eq!(hosts[0]["changed"], true);
    assert_eq!(
        hosts[0]["settings_path"],
        sb.home
            .join(".codex")
            .join("hooks.json")
            .display()
            .to_string()
    );

    assert!(!sb.home.join(".moat/policy.lock").exists());
    assert!(!sb.home.join(".codex/hooks.json").exists());
    assert!(!sb.home.join(".claude/settings.json").exists());
    assert_eq!(
        std::fs::read_to_string(&config_toml).unwrap(),
        "model = \"gpt-5\"\n"
    );
}

#[test]
fn hooks_only_preserves_sandbox_mcp_and_other_hosts_and_is_idempotent() {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let codex_config = sb.home.join(".codex/config.toml");
    let mcp_json = sb.home.join(".claude.json");
    std::fs::write(&codex_config, "model = \"gpt-5\"\n").unwrap();
    std::fs::write(
        &mcp_json,
        r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#,
    )
    .unwrap();

    // First, install and wrap claude-code so policy.lock already has claude + MCP pins.
    let init_claude =
        sb.moat_as_person(&["init", "--hosts", "claude-code", "--yes", "--mcp-proxy"]);
    assert_eq!(
        init_claude.status.code(),
        Some(OK),
        "{}",
        text(&init_claude)
    );
    let mcp_before = std::fs::read_to_string(&mcp_json).unwrap();
    let lock_before: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    let mcp_pins_before = lock_before["mcp_servers"].clone();
    assert!(!mcp_pins_before.is_null());

    // Now install ONLY codex hooks via --hooks-only --format json.
    let out = sb.moat(&[
        "init",
        "--hooks-only",
        "--yes",
        "--format",
        "json",
        "--hosts",
        "codex",
    ]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["dry_run"], false);
    assert_eq!(doc["hooks_only"], true);
    assert_eq!(doc["changed"], true);
    assert!(doc["lock_entries_count"].as_u64().is_some_and(|n| n > 0));
    let hosts = doc["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["host"], "codex");
    assert_eq!(hosts[0]["outcome"], "installed");

    // Codex sandbox and Claude MCP config were untouched.
    assert_eq!(
        std::fs::read_to_string(&codex_config).unwrap(),
        "model = \"gpt-5\"\n"
    );
    assert_eq!(std::fs::read_to_string(&mcp_json).unwrap(), mcp_before);

    // policy.lock kept claude-code and mcp_servers while adding codex hooks.json
    // and keeping codex_profiles empty.
    let lock_after: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    assert_eq!(lock_after["mcp_servers"], mcp_pins_before);
    assert!(lock_after.get("codex_profiles").is_none());
    let entries = lock_after["entries"].as_object().unwrap();
    let claude_suffix = Path::new(".claude").join("settings.json");
    let codex_suffix = Path::new(".codex").join("hooks.json");
    assert!(
        entries
            .keys()
            .any(|k| Path::new(k).ends_with(&claude_suffix)),
        "expected claude settings in lock entries: {entries:?}"
    );
    assert!(
        entries.keys().any(|k| Path::new(k).ends_with(&codex_suffix)),
        "expected codex hooks in lock entries: {entries:?}"
    );

    // Re-running with the same flags is a no-op (idempotent).
    let second = sb.moat(&[
        "init",
        "--hooks-only",
        "--yes",
        "--format",
        "json",
        "--hosts",
        "codex",
    ]);
    assert_eq!(second.status.code(), Some(OK), "{}", text(&second));
    let doc2: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(doc2["changed"], false);
    assert_eq!(doc2["hosts"][0]["outcome"], "unchanged");

    // Lock, binary, hook, and MCP checks report zero problems without enabling Codex OS sandbox.
    let doctor = sb.moat(&["doctor", "--format", "json"]);
    let doctor_doc: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let checks = doctor_doc["checks"].as_array().unwrap();
    let lock_ok = checks
        .iter()
        .any(|c| c["area"] == "lock" && c["status"] == "ok");
    assert!(lock_ok, "expected ok lock check in {checks:?}");
    let core_problems: Vec<&Value> = checks
        .iter()
        .filter(|c| {
            c["status"] == "problem"
                && matches!(
                    c["area"].as_str(),
                    Some("state" | "policy" | "lock" | "binary" | "hook" | "mcp")
                )
        })
        .collect();
    assert!(
        core_problems.is_empty(),
        "unexpected core problems: {core_problems:?}"
    );

    let deny_payload = r#"{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}"#;
    let denied = sb.guard("codex", deny_payload);
    assert_eq!(
        denied.status.code(),
        Some(crate::common::DENY),
        "{}",
        text(&denied)
    );

    let allow_payload = r#"{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let allowed = sb.guard("codex", allow_payload);
    assert_eq!(allowed.status.code(), Some(OK), "{}", text(&allowed));
}

#[test]
fn hooks_only_conflicts_with_mcp_proxy() {
    let sb = Sandbox::bare(&[".codex"]);
    let out = sb.moat(&["init", "--hooks-only", "--mcp-proxy", "--hosts", "codex"]);
    assert_ne!(out.status.code(), Some(OK));
}
