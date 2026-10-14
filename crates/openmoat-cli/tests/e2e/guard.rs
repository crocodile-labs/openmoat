//! End-to-end tests of `moat init`, `moat guard`, `moat show` and `moat status`
//! inside an isolated HOME.

use serde_json::Value;

use crate::common::{Sandbox, fixture, hook_output as decision, stderr, stdout};

mod tools;

/// The parsed `~/.claude/settings.json`.
fn settings(sb: &Sandbox) -> Value {
    let text = std::fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn init_creates_state_and_installs_claude_code_hook() {
    let sb = Sandbox::bare(&[".claude"]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("installed: PreToolUse, ConfigChange →"));
    assert!(sb.home.join(".moat/policy.yaml").is_file());
    assert!(sb.home.join(".moat/audit.db").is_file());

    let hooks = &settings(&sb)["hooks"]["PreToolUse"];
    assert_eq!(hooks.as_array().unwrap().len(), 1);
    assert_eq!(
        hooks[0]["hooks"][0]["args"],
        serde_json::json!(["guard", "--host", "claude-code"])
    );
    let command = hooks[0]["hooks"][0]["command"].as_str().unwrap();
    assert!(
        command.ends_with("moat") || command.ends_with("moat.exe"),
        "{command}"
    );

    let again = sb.moat(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(0));
    assert!(stdout(&again).contains("unchanged"));
    assert!(stdout(&again).contains("(kept)"));
    assert_eq!(
        settings(&sb)["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", stdout(&status));
    assert!(stdout(&status).contains("✔ installed"));
}

#[test]
fn init_dry_run_touches_nothing() {
    let sb = Sandbox::bare(&[".claude"]);
    let out = sb.moat(&["init", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("would"));
    assert!(!sb.home.join(".moat").exists());
    assert!(!sb.home.join(".claude/settings.json").exists());
}

#[test]
fn guard_denies_secret_exfiltration_and_records_it() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);

    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert_eq!(out.status.code(), Some(2));
    let d = decision(&out);
    assert_eq!(d["hookEventName"], "PreToolUse");
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("secrets-paths")
    );
    assert!(stderr(&out).contains("moat show "));

    let shown = sb.moat(&["show", "--recent", "1"]);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let text = stdout(&shown);
    assert!(text.starts_with("id     time (UTC) host"), "{text}");
    assert!(text.contains("deny"));
    assert!(text.contains("curl -d @~/.ssh/id_rsa"));

    let id = stderr(&out)
        .lines()
        .find_map(|l| l.strip_prefix("moat: trace "))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("trace id")
        .to_owned();
    let detail = sb.moat(&["show", &id]);
    assert_eq!(detail.status.code(), Some(0));
    assert!(stdout(&detail).contains("session 7c1e4b2a"));
    assert!(stdout(&detail).contains("secrets-paths"));

    let json = sb.moat(&["show", &id, "--format", "json"]);
    let events: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(events[0]["verdict"], "deny");
    assert_eq!(events[0]["tool"], "Bash");
    assert_eq!(events[0]["id"], id.as_str());
}

#[test]
fn guard_allows_ordinary_work_and_defers_installs() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let cwd = project.to_string_lossy();

    let payload = |command: &str| {
        serde_json::json!({
            "session_id": "s-allow", "cwd": cwd, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t1"
        })
        .to_string()
    };

    for (command, verdict, rule) in [
        ("git status --short", "allow", "dev-shell"),
        // ADR-025: no rule matches an install; the agent's own prompt decides
        ("npm install left-pad-pro", "defer", ""),
    ] {
        let out = sb.guard("claude-code", &payload(command));
        assert_eq!(out.status.code(), Some(0), "{command}: {}", stderr(&out));
        let d = decision(&out);
        assert_eq!(d["permissionDecision"], verdict, "{command}");
        assert!(
            d["permissionDecisionReason"].to_string().contains(rule),
            "{command}: {d}"
        );
    }

    let edit = serde_json::json!({
        "session_id": "s-allow", "cwd": cwd, "tool_name": "Write",
        "tool_input": {"file_path": project.join("src/main.rs").to_string_lossy(), "content": "fn main(){}"}
    });
    let out = sb.guard("claude-code", &edit.to_string());
    let d = decision(&out);
    assert_eq!(d["permissionDecision"], "allow", "{}", stderr(&out));
    assert!(
        d["permissionDecisionReason"]
            .to_string()
            .contains("project-fs"),
        "{d}"
    );

    let since = sb.moat(&["show", "--since", "1h"]);
    assert_eq!(since.status.code(), Some(0), "{}", stderr(&since));
    assert_eq!(
        stdout(&since).lines().count(),
        4,
        "header + three events:\n{}",
        stdout(&since)
    );
    let bad = sb.moat(&["show", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(64));
    assert!(stderr(&bad).contains("time window"));

    let session = sb.moat(&["show", "--session", "s-allow"]);
    assert_eq!(
        stdout(&session).lines().count(),
        4,
        "header + three events:\n{}",
        stdout(&session)
    );
}

#[test]
fn guard_passes_ungoverned_tools_through() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let out = sb.guard("claude-code", &fixture("claude-code/ungoverned.json"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(decision(&out)["permissionDecision"], "allow");
    assert!(
        decision(&out)["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ungoverned")
    );
}

#[test]
fn claude_code_command_tools_are_hooked_and_governed() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let matcher = settings(&sb)["hooks"]["PreToolUse"][0]["matcher"]
        .as_str()
        .unwrap()
        .to_owned();
    for tool in ["Bash", "Monitor", "PowerShell", "LSP", "SendFile"] {
        assert!(matcher.split('|').any(|m| m == tool), "{tool} in {matcher}");
    }

    for name in ["monitor", "sendfile"] {
        let out = sb.guard("claude-code", &fixture(&format!("claude-code/{name}.json")));
        assert_eq!(out.status.code(), Some(2), "{name}");
        let d = decision(&out);
        assert_eq!(d["permissionDecision"], "deny", "{name}");
        let reason = d["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("secrets-paths"), "{name}: {reason}");
    }

    let ps = sb.guard("claude-code", &fixture("claude-code/powershell.json"));
    assert_eq!(ps.status.code(), Some(0));
    let d = decision(&ps);
    assert_eq!(d["permissionDecision"], "defer");
    let shown = stdout(&sb.moat(&["show", "--recent", "1"]));
    assert!(shown.contains("unparseable"), "{shown}");
    assert!(shown.contains("PowerShell"), "{shown}");
}

#[test]
fn guard_fails_closed() {
    let sb = Sandbox::bare(&[".claude"]);

    let out = sb.guard("claude-code", &fixture("claude-code/read.json"));
    assert_eq!(out.status.code(), Some(2), "no policy installed must deny");
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    assert!(
        decision(&out)["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("moat init")
    );

    sb.moat(&["init", "--yes"]);
    for payload in ["", "not json", r#"{"tool_name":"Bash","tool_input":{}}"#] {
        let out = sb.guard("claude-code", payload);
        assert_eq!(out.status.code(), Some(2), "payload {payload:?} must deny");
        assert_eq!(decision(&out)["permissionDecision"], "deny");
        assert_eq!(
            decision(&out)["permissionDecisionReason"]
                .as_str()
                .map(|r| r.contains("kernel-error")),
            Some(true)
        );
    }
}

/// Hosts block a call only on exit 2, so a hook command line `guard` cannot
/// parse (an unknown host, a missing or misspelt flag after an upgrade) must
/// deny rather than fail open with the usage code (ADR-015).
#[test]
fn unparseable_guard_arguments_deny() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    for args in [
        &["guard", "--host", "windsurf"][..],
        &["guard"],
        &["guard", "--hots", "claude-code"],
        &["guard", "--host", "claude-code", "extra"],
    ] {
        let out = sb.moat_stdin(args, "{}");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(!stderr(&out).is_empty(), "{args:?} must say why");
    }
    let help = sb.moat(&["guard", "--help"]);
    assert_eq!(help.status.code(), Some(0), "help is not a failure");
    let other = sb.moat(&["show", "--since", "soon"]);
    assert_eq!(
        other.status.code(),
        Some(64),
        "other commands keep the usage code"
    );
}

#[test]
fn malformed_payloads_name_their_cause_once() {
    let sb = Sandbox::installed(&[".claude"]);
    for (payload, problem, cause) in [
        ("nope", "payload is not valid JSON", "expected ident"),
        (
            "[1]",
            "payload is JSON but does not fit the hook schema",
            "invalid type",
        ),
    ] {
        let out = sb.guard("claude-code", payload);
        assert_eq!(out.status.code(), Some(2), "payload {payload:?} must deny");
        let reason = decision(&out)["permissionDecisionReason"].to_string();
        assert!(reason.contains(problem), "{reason}");
        assert_eq!(reason.matches(cause).count(), 1, "{reason}");
    }
}

#[test]
fn deleted_audit_log_denies_instead_of_recreating_it() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let audit = sb.home.join(".moat/audit.db");
    let before = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert!(
        !stderr(&before).contains("audit log unavailable"),
        "{}",
        stderr(&before)
    );

    std::fs::remove_file(&audit).unwrap();
    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    let reason = decision(&out)["permissionDecisionReason"].to_string();
    assert!(reason.contains("kernel-error"), "{reason}");
    assert!(reason.contains("audit log unavailable"), "{reason}");
    assert!(!audit.exists(), "guard must not quietly create a fresh log");
}

#[cfg(unix)]
#[test]
fn unwritable_audit_log_denies() {
    use std::os::unix::fs::PermissionsExt as _;
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let audit = sb.home.join(".moat/audit.db");
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    assert!(
        stderr(&out).contains("audit log unavailable"),
        "{}",
        stderr(&out)
    );
}

/// Symlinks are only created on Unix here; Windows needs a privilege for them.
#[cfg(unix)]
#[test]
fn reads_and_writes_through_symlinks_are_checked_at_the_target() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "key").unwrap();
    std::os::unix::fs::symlink(sb.home.join(".ssh"), project.join("s")).unwrap();
    let cwd = project.to_string_lossy();
    let bash = |command: &str| {
        serde_json::json!({
            "session_id": "s-link", "cwd": cwd, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t1"
        })
        .to_string()
    };

    for command in ["cat ./s/id_rsa", "echo k >> s/authorized_keys"] {
        let out = sb.guard("claude-code", &bash(command));
        assert_eq!(out.status.code(), Some(2), "{command}: {}", stderr(&out));
        let reason = decision(&out)["permissionDecisionReason"].to_string();
        assert!(reason.contains("secrets-paths"), "{command}: {reason}");
        assert!(reason.contains(".ssh/"), "{command}: {reason}");
    }
    let read = serde_json::json!({
        "session_id": "s-link", "cwd": cwd, "tool_name": "Read",
        "tool_input": {"file_path": project.join("s/id_rsa").to_string_lossy()}
    });
    let out = sb.guard("claude-code", &read.to_string());
    assert_eq!(decision(&out)["permissionDecision"], "deny");

    let out = sb.guard("claude-code", &bash("cat ./src/main.rs"));
    assert_eq!(
        decision(&out)["permissionDecision"],
        "allow",
        "{}",
        stderr(&out)
    );
}

/// Windows payloads carry drive-letter paths; they must reach the policy in the
/// same canonical form as `${project}` and `~` (no `\\?\` verbatim prefix).
#[cfg(windows)]
#[test]
fn windows_drive_letter_payloads_are_canonical() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let slash = |p: &std::path::Path| p.to_string_lossy().replace('\\', "/");
    let cwd = slash(&project);
    let tool = |name: &str, input: serde_json::Value| {
        serde_json::json!({
            "session_id": "s-win", "cwd": cwd, "hook_event_name": "PreToolUse",
            "tool_name": name, "tool_input": input, "tool_use_id": "t1"
        })
        .to_string()
    };

    let write = tool(
        "Write",
        serde_json::json!({"file_path": format!("{cwd}/src/main.rs"), "content": "x"}),
    );
    let out = sb.guard("claude-code", &write);
    assert_eq!(
        decision(&out)["permissionDecision"],
        "allow",
        "{}",
        stderr(&out)
    );

    let key = format!("{}/.ssh/id_rsa", slash(&sb.home));
    let out = sb.guard(
        "claude-code",
        &tool("Read", serde_json::json!({"file_path": key})),
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let reason = decision(&out)["permissionDecisionReason"].to_string();
    assert!(reason.contains("secrets-paths"), "{reason}");
}

#[test]
fn codex_payloads_use_the_same_contract() {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".codex")).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert!(stdout(&out).contains("Codex"), "{}", stdout(&out));
    assert!(sb.home.join(".codex/hooks.json").is_file());

    let hooks = std::fs::read_to_string(sb.home.join(".codex/hooks.json")).unwrap();
    assert!(hooks.contains("Bash|apply_patch|mcp__.*"), "{hooks}");

    for (payload, rule) in [
        ("codex/pretooluse-shell.json", "env-poison"),
        ("codex/pretooluse-apply-patch.json", "shell-rc"),
        ("codex/pretooluse-patch-indented.json", "secrets-paths"),
        ("codex/pretooluse-mcp.json", "secrets-paths"),
    ] {
        let out = sb.guard("codex", &fixture(payload));
        assert_eq!(out.status.code(), Some(2), "{payload}: {}", stderr(&out));
        let reason = decision(&out)["permissionDecisionReason"].to_string();
        assert!(reason.contains(rule), "{payload}: {reason}");
    }
}

#[test]
fn status_reports_missing_installation() {
    let sb = Sandbox::bare(&[".claude"]);
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stdout(&out).contains("run `moat init`"));
    assert!(!stdout(&out).contains("os error"), "{}", stdout(&out));
}
