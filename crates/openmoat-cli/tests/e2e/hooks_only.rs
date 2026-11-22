//! `openmoat init --hooks-only --format json`: installs and pins only the
//! selected host hooks without touching agent sandboxes, MCP wrapping, or
//! the other hosts' pins in `policy.lock`; with no lock to keep, every
//! installed hook is pinned. Neither flag asks a question.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, output, squash, stdout, text};
use crate::hosts::{dir_of, hook_file, mcp_user_file};
use openmoat_hosts::Host;

/// The agent `--hooks-only` sets up here, and the one set up before it.
const CHOSEN: Host = Host::Codex;
const OTHER: Host = Host::ClaudeCode;

/// A sandbox with both agents' directories.
fn sandbox() -> Sandbox {
    Sandbox::bare(&[&dir_of(OTHER), &dir_of(CHOSEN)])
}

/// The file beside the chosen agent's hook file its sandbox is written to.
fn sandbox_file(sb: &Sandbox) -> PathBuf {
    let sandbox = CHOSEN.spec().sandbox.as_ref().unwrap();
    hook_file(sb, CHOSEN).with_file_name(sandbox.file)
}

fn lock(sb: &Sandbox) -> Value {
    serde_json::from_str(&std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
        .unwrap()
}

/// Whether `lock` pins `host`'s hook file.
fn pins_hook(sb: &Sandbox, lock: &Value, host: Host) -> bool {
    let hook = hook_file(sb, host);
    let relative = hook.strip_prefix(&sb.home).unwrap();
    lock["entries"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| Path::new(k).ends_with(relative))
}

#[test]
fn hooks_only_dry_run_json_writes_nothing_and_plans_selected_host() {
    let sb = sandbox();
    let config_toml = sandbox_file(&sb);
    std::fs::write(&config_toml, "model = \"gpt-5\"\n").unwrap();

    let out = sb.moat(&[
        "init",
        "--hooks-only",
        "--dry-run",
        "--format",
        "json",
        "--hosts",
        CHOSEN.id(),
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
    assert_eq!(hosts[0]["host"], CHOSEN.id());
    assert_eq!(hosts[0]["outcome"], "installed");
    assert_eq!(hosts[0]["changed"], true);
    assert_eq!(
        hosts[0]["settings_path"],
        hook_file(&sb, CHOSEN).display().to_string()
    );

    assert!(!sb.home.join(".moat/policy.lock").exists());
    assert!(!hook_file(&sb, CHOSEN).exists());
    assert!(!hook_file(&sb, OTHER).exists());
    assert_eq!(
        std::fs::read_to_string(&config_toml).unwrap(),
        "model = \"gpt-5\"\n"
    );
}

#[test]
fn hooks_only_preserves_sandbox_mcp_and_other_hosts_and_is_idempotent() {
    let sb = sandbox();
    let codex_config = sandbox_file(&sb);
    let mcp_json = mcp_user_file(&sb, OTHER);
    std::fs::write(&codex_config, "model = \"gpt-5\"\n").unwrap();
    std::fs::write(
        &mcp_json,
        r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#,
    )
    .unwrap();

    // First, install and wrap the other agent so the lock already has its
    // hook and MCP pins.
    let init_other = sb.moat_as_person(&["init", "--hosts", OTHER.id(), "--yes", "--mcp-proxy"]);
    assert_eq!(init_other.status.code(), Some(OK), "{}", text(&init_other));
    let mcp_before = std::fs::read_to_string(&mcp_json).unwrap();
    let mcp_pins_before = lock(&sb)["mcp_servers"].clone();
    assert!(!mcp_pins_before.is_null());

    // Now install only the chosen agent's hooks, `--hooks-only --format json`.
    let args = [
        "init",
        "--hooks-only",
        "--yes",
        "--format",
        "json",
        "--hosts",
        CHOSEN.id(),
    ];
    let out = sb.moat(&args);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["dry_run"], false);
    assert_eq!(doc["hooks_only"], true);
    assert_eq!(doc["changed"], true);
    assert!(doc["lock_entries_count"].as_u64().is_some_and(|n| n > 0));
    let hosts = doc["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["host"], CHOSEN.id());
    assert_eq!(hosts[0]["outcome"], "installed");

    // The chosen agent's sandbox and the other's MCP configuration were untouched.
    assert_eq!(
        std::fs::read_to_string(&codex_config).unwrap(),
        "model = \"gpt-5\"\n"
    );
    assert_eq!(std::fs::read_to_string(&mcp_json).unwrap(), mcp_before);

    // The lock kept the other agent's hook and the MCP pins, added the chosen
    // agent's hook file and pins no sandbox profile for it.
    let lock_after = lock(&sb);
    assert_eq!(lock_after["mcp_servers"], mcp_pins_before);
    assert!(lock_after.get("codex_profiles").is_none());
    assert!(pins_hook(&sb, &lock_after, OTHER), "{lock_after}");
    assert!(pins_hook(&sb, &lock_after, CHOSEN), "{lock_after}");

    // Re-running with the same flags is a no-op (idempotent).
    let second = sb.moat(&args);
    assert_eq!(second.status.code(), Some(OK), "{}", text(&second));
    let doc2: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(doc2["changed"], false);
    assert_eq!(doc2["hosts"][0]["outcome"], "unchanged");

    // Lock, binary, hook, and MCP checks report zero problems without the
    // chosen agent's OS sandbox.
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
    let denied = sb.guard(CHOSEN.id(), deny_payload);
    assert_eq!(denied.status.code(), Some(DENY), "{}", text(&denied));

    let allow_payload = r#"{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let allowed = sb.guard(CHOSEN.id(), allow_payload);
    assert_eq!(allowed.status.code(), Some(OK), "{}", text(&allowed));
}

#[test]
fn hooks_only_conflicts_with_mcp_proxy() {
    let sb = sandbox();
    let out = sb.moat(&[
        "init",
        "--hooks-only",
        "--mcp-proxy",
        "--hosts",
        CHOSEN.id(),
    ]);
    assert_ne!(out.status.code(), Some(OK));
}

/// Another agent's hook installed and no lock (one deleted, or never
/// written): `--hooks-only` writes only the chosen agent's hook but pins every
/// installed one, so the other's file cannot change unseen.
#[test]
fn hooks_only_without_a_lock_pins_every_installed_hook() {
    let sb = sandbox();
    let first = sb.moat(&["init", "--hosts", OTHER.id()]);
    assert_eq!(first.status.code(), Some(OK), "{}", text(&first));
    std::fs::remove_file(sb.home.join(".moat/policy.lock")).unwrap();

    let out = sb.moat(&["init", "--hooks-only", "--hosts", CHOSEN.id()]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let lock = lock(&sb);
    assert!(pins_hook(&sb, &lock, CHOSEN), "{lock}");
    assert!(pins_hook(&sb, &lock, OTHER), "{lock}");
}

/// `--format json` prints no question, so it refuses to choose the agents by
/// asking, and writes nothing.
#[test]
fn json_without_hosts_or_yes_is_refused_before_anything_is_written() {
    let sb = Sandbox::bare(&[&dir_of(OTHER)]);
    let out = sb.moat_as_person(&["init", "--format", "json"]);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("--hosts"), "{}", text(&out));
    assert!(out.stdout.is_empty(), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists());
    assert!(!hook_file(&sb, OTHER).exists());
}

/// A person at a terminal is asked nothing by `--format json` or
/// `--hooks-only`: not the opt-in questions (ADR-106), not whether to wrap the
/// MCP servers. Every answer offered here is a yes that would show.
#[test]
fn json_and_hooks_only_ask_no_question_of_a_person() {
    for flags in [
        &["--format", "json"][..],
        &["--hooks-only"][..],
        &["--hooks-only", "--format", "json"][..],
    ] {
        let sb = Sandbox::bare(&[&dir_of(OTHER)]);
        let mcp_json = mcp_user_file(&sb, OTHER);
        let servers = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-server"]}}}"#;
        std::fs::write(&mcp_json, servers).unwrap();
        let mut args = vec!["init", "--hosts", OTHER.id()];
        args.extend_from_slice(flags);
        let out = output(
            sb.command().args(&args).env("MOAT_ASSUME_TTY", "1"),
            Some("y\ny\ny\n"),
        );
        assert_eq!(out.status.code(), Some(OK), "{flags:?}: {}", text(&out));
        let shown = squash(&stdout(&out));
        for question in [
            "Decoy keys plant",
            "Sandboxed start",
            "Run them through OpenMoat?",
        ] {
            assert!(
                !shown.contains(question),
                "{flags:?} asked {question}: {shown}"
            );
        }
        assert!(!sb.home.join(".npmrc.bak").exists(), "{flags:?}");
        assert_eq!(
            std::fs::read_to_string(&mcp_json).unwrap(),
            servers,
            "{flags:?}"
        );
        if flags.contains(&"json") {
            let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(doc["hosts"][0]["host"], OTHER.id(), "{doc}");
            assert_eq!(
                doc["binary_sha256"],
                lock(&sb)["binary_sha256"],
                "the hash the lock recorded"
            );
        }
    }
}
