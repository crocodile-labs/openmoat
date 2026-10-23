//! Each agent's protection level in `moat status` (text and JSON), `moat doctor`
//! and the home screen (#334).

use std::fs;

use openmoat_hosts::Host;
use serde_json::Value;

use crate::common::{OK, Sandbox, json, output, stdout, text};

/// The `agents` entry of `moat status --format json` for `host`.
fn agent(sb: &Sandbox, host: &str) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    json(&out)["agents"]
        .as_array()
        .and_then(|agents| agents.iter().find(|a| a["host"] == host).cloned())
        .unwrap_or_else(|| panic!("{host} missing: {}", text(&out)))
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn each_agent_reports_its_level_and_gaps() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let status = stdout(&sb.moat(&["status"]));
    for line in [
        "Claude Code      ✔ protection: hook + OS sandbox",
        "Claude Code      · known gaps: file tools, WebFetch and MCP servers run outside the OS sandbox",
        "Codex            ✔ protection: hook + OS sandbox",
        "Codex            · known gaps: web search and hosted tools are not hooked; asks become denies",
        "Cursor           ✔ protection: hook + OS sandbox",
        "Cursor           · known gaps: commands Cursor runs outside its sandbox",
    ] {
        assert!(status.contains(line), "{line:?} in {status}");
    }
    let doctor = stdout(&sb.moat(&["doctor"]));
    assert!(
        doctor.contains("· Codex            protection: hook + OS sandbox"),
        "{doctor}"
    );
    assert!(
        doctor.contains("· Cursor           protection: hook + OS sandbox"),
        "{doctor}"
    );
    assert!(doctor.contains("healthy"), "{doctor}");

    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-and-os-sandbox", "{claude}");
    assert_eq!(claude["reason"], Value::Null, "{claude}");
    assert_eq!(claude["name"], "Claude Code");
    let gaps = claude["gaps"].as_str().unwrap();
    assert!(
        gaps.contains("MCP servers") && !gaps.contains("WebSearch"),
        "{gaps}"
    );
    let cursor = agent(&sb, "cursor");
    assert_eq!(cursor["level"], "hook-and-os-sandbox", "{cursor}");

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains(
            "Protecting Claude Code (hook + OS sandbox), Codex (hook + OS sandbox), Cursor (hook + OS sandbox)"
        ),
        "{home}"
    );
}

#[test]
fn a_drifted_sandbox_is_hook_only_and_says_which() {
    let sb = Sandbox::installed(&[".codex"]);
    let path = sb.home.join(".codex/config.toml");
    let weakened = fs::read_to_string(&path).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(&path, weakened).unwrap();
    let codex = agent(&sb, "codex");
    assert_eq!(codex["level"], "hook-only", "{codex}");
    let reason = codex["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("sandbox: default_permissions is not \"moat\""),
        "{reason}"
    );
    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Codex            ! protection: hook only: sandbox: default_permissions"),
        "{status}"
    );
}

#[test]
fn a_missing_hook_is_not_protected_and_absent_agents_keep_their_line() {
    let sb = Sandbox::installed(&[".claude"]);
    fs::write(sb.home.join(".claude/settings.json"), "{}").unwrap();
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "not-protected", "{claude}");
    assert_eq!(claude["reason"], "hook missing", "{claude}");
    assert_eq!(agent(&sb, "codex")["level"], "not-found");

    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Claude Code      ✗ protection: not protected: hook missing"),
        "{status}"
    );
    assert!(
        status.contains("Codex            · host not found"),
        "{status}"
    );
    assert!(!status.contains("Codex            ✗"), "{status}");
    assert!(
        !status.contains("Codex            · known gaps"),
        "{status}"
    );

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(home.contains("No agent is protected"), "{home}");
}

/// A Claude Code older than 2.1.295 gets no `onFailure` and `doctor` says the
/// call then runs when the hook fails; once Claude Code is updated the hook is
/// out of date until `moat init` adds the key.
#[test]
fn an_older_claude_code_gets_no_on_failure_until_it_is_updated() {
    let sb = Sandbox::bare(&[".claude"]);
    let old = |args: &[&str]| {
        output(
            sb.command()
                .args(args)
                .env("MOAT_CLAUDE_CODE_VERSION", "2.1.200 (Claude Code)"),
            None,
        )
    };
    let out = old(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let settings = sb.home.join(".claude/settings.json");
    let handler = || -> Value {
        let doc: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"][0]["hooks"][0].clone()
    };
    assert!(handler().get("onFailure").is_none(), "{}", handler());
    let doctor = stdout(&old(&["doctor"]));
    assert!(doctor.contains("no `onFailure: \"block\"`"), "{doctor}");
    assert_eq!(agent(&sb, "claude-code")["reason"], "hook out of date");

    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(handler()["onFailure"], "block");
    let doctor = stdout(&sb.moat(&["doctor"]));
    assert!(!doctor.contains("onFailure"), "{doctor}");
}

/// #327: Claude Code's sandbox cannot run on native Windows, so its hook is all
/// OpenMoat gives it there.
#[cfg(windows)]
#[test]
fn claude_code_on_native_windows_is_hook_only() {
    let sb = Sandbox::installed(&[".claude"]);
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-only", "{claude}");
    assert!(
        claude["reason"]
            .as_str()
            .unwrap()
            .starts_with("sandbox not available on native Windows"),
        "{claude}"
    );
    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Claude Code      ! protection: hook only: sandbox not available"),
        "{status}"
    );
    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains("Protecting Claude Code (hook only)"),
        "{home}"
    );
}

/// Each host's label in the sections of `moat status` and `moat doctor`: its
/// name, cut to the 16-character label column.
fn host_labels() -> Vec<String> {
    Host::ALL
        .iter()
        .map(|host| host.display_name().chars().take(16).collect())
        .collect()
}

/// `before`, every host's label in `Host::ALL` order, then the audit log.
fn with_hosts(before: &[&str]) -> Vec<String> {
    let before = before.iter().map(|label| (*label).to_owned());
    before
        .chain(host_labels())
        .chain(["audit log".to_owned()])
        .collect()
}

/// The first line of each section of `moat status` and `moat doctor`, in the
/// order they print: the label column after `skip` leading characters (the
/// check mark in `doctor`).
fn sections(out: &str, skip: usize) -> Vec<String> {
    let known = with_hosts(&[
        "state directory",
        "policy",
        "lock",
        "approvals",
        "environment",
    ]);
    let mut seen: Vec<String> = Vec::new();
    for line in out.lines() {
        let label = line.chars().skip(skip).take(16).collect::<String>();
        let label = label.trim_end();
        if known.iter().any(|k| k == label) && !seen.iter().any(|s| s == label) {
            seen.push(label.to_owned());
        }
    }
    seen
}

#[test]
fn status_and_doctor_print_their_sections_in_order() {
    let sb = Sandbox::installed(&[".codex"]);
    let status = stdout(&sb.moat(&["status"]));
    assert_eq!(
        sections(&status, 0),
        with_hosts(&["state directory", "policy", "lock", "approvals"]),
        "{status}"
    );
    let doctor = stdout(&sb.moat(&["doctor"]));
    assert_eq!(
        sections(&doctor, 2),
        with_hosts(&["state directory", "policy", "lock", "environment"]),
        "{doctor}"
    );
    assert_eq!(doctor.lines().last(), Some("healthy"), "{doctor}");
}

#[test]
fn status_and_doctor_report_a_missing_lock_and_audit_log() {
    let sb = Sandbox::installed(&[".codex"]);
    fs::remove_file(sb.home.join(".moat/policy.lock")).unwrap();
    fs::remove_file(sb.home.join(".moat/audit.db")).unwrap();
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let status = stdout(&out);
    for line in [
        "lock             ✗ missing (run `openmoat init`)",
        "approvals        no active session grants",
        "audit log        ✗ missing (run `openmoat init`)",
    ] {
        assert!(status.lines().any(|l| l == line), "{line:?} in {status}");
    }
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let doctor = stdout(&out);
    assert!(
        doctor
            .lines()
            .any(|l| l == "✗ lock             missing; run `openmoat init`"),
        "{doctor}"
    );
    assert!(
        doctor.lines().any(|l| l.starts_with("✗ audit log        ")),
        "{doctor}"
    );
    assert!(
        doctor
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("2 problem(s). ")),
        "{doctor}"
    );
}

/// `moat doctor --format json`: the same rows as the text, one document, and
/// the same exit code; nothing else on stdout.
#[test]
fn doctor_prints_its_checks_as_one_json_document() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["doctor", "--format", "json"]);
    let doc = json(&out);
    let checks = doc["checks"].as_array().expect("checks");
    assert!(!checks.is_empty(), "{}", text(&out));
    assert_eq!(
        doc["healthy"],
        out.status.code() == Some(OK),
        "{}",
        text(&out)
    );
    assert!(
        checks
            .iter()
            .any(|c| c["status"] == "ok" && c["name"] == "state directory"),
        "{}",
        text(&out)
    );
    assert!(
        checks
            .iter()
            .all(|c| ["ok", "problem", "warning", "note"]
                .contains(&c["status"].as_str().unwrap_or(""))),
        "{}",
        text(&out)
    );
    let refused = sb.moat(&["doctor", "--format", "json", "--accept"]);
    assert_ne!(refused.status.code(), Some(OK), "json never accepts");
}

/// `moat status --format json` also says whether a policy update waits for
/// `moat policy upgrade` and which pinned files changed, for tools such as the
/// menu bar app that show them.
#[test]
fn status_json_reports_a_waiting_update_and_lock_drift() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["status", "--format", "json"]);
    let doc = json(&out);
    assert!(doc["policy_update"].is_null(), "{}", text(&out));
    assert_eq!(doc["lock_drift"], serde_json::json!([]), "{}", text(&out));

    let policy = sb.home.join(".moat/policy.yaml");
    let edited = fs::read_to_string(&policy).unwrap() + "\n# edited by hand\n";
    fs::write(&policy, edited).unwrap();
    let doc = json(&sb.moat(&["status", "--format", "json"]));
    let drift = doc["lock_drift"].as_array().unwrap();
    assert!(
        drift
            .iter()
            .any(|d| d.as_str().unwrap().contains("policy.yaml")),
        "{doc}"
    );
}
