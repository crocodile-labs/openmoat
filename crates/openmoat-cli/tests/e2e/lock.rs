//! Self-protection: the policy lock and fail-closed `guard` on tampering.

use std::path::PathBuf;

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, USAGE, fixture, hook_output, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".claude"])
}

/// `guard` on the golden `Read src/lib.rs` payload, with the exit code folded in.
fn guard_read_src(sb: &Sandbox) -> Value {
    let out = sb.guard("claude-code", &fixture("claude-code/read.json"));
    let mut d = hook_output(&out);
    d["exit"] = Value::from(out.status.code().unwrap_or(-1));
    d
}

fn policy_path(sb: &Sandbox) -> PathBuf {
    sb.home.join(".moat/policy.yaml")
}

fn lock_path(sb: &Sandbox) -> PathBuf {
    sb.home.join(".moat/policy.lock")
}

fn settings_path(sb: &Sandbox) -> PathBuf {
    sb.home.join(".claude/settings.json")
}

#[test]
fn init_writes_a_lock_covering_policy_and_hooks() {
    let sb = sandbox();
    let lock: Value =
        serde_json::from_str(&std::fs::read_to_string(lock_path(&sb)).unwrap()).unwrap();
    let entries = lock["entries"].as_object().unwrap();
    assert_eq!(entries.len(), 7, "{entries:?}");
    // No `openmoat trust` yet: its file is pinned as missing, so one planted
    // there is drift.
    let trust = entries.iter().find(|(k, _)| k.ends_with("trust.json"));
    assert_eq!(trust.map(|(_, v)| v.as_str()), Some(Some("absent")));
    for name in [
        "hosts.json",
        "policy.yaml",
        "environment.json",
        "approvals.json",
        "approved.yaml",
    ] {
        assert!(
            entries.keys().any(|k| k.ends_with(name)),
            "{name} not pinned: {entries:?}"
        );
    }
    assert!(entries.keys().any(|k| k.ends_with("settings.json")));
}

#[test]
fn edited_policy_makes_guard_fail_closed_until_repinned() {
    let sb = sandbox();
    assert_eq!(guard_read_src(&sb)["permissionDecision"], "allow");

    let mut policy = std::fs::read_to_string(policy_path(&sb)).unwrap();
    policy.push_str("\n# tampered by an agent\n");
    std::fs::write(policy_path(&sb), policy).unwrap();

    let d = guard_read_src(&sb);
    assert_eq!(d["permissionDecision"], "deny");
    assert_eq!(d["exit"], 2);
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(reason.contains("policy.yaml"), "{reason}");

    let check = sb.moat(&["policy", "check", "git status"]);
    assert_eq!(check.status.code(), Some(DENY), "{}", text(&check));
    assert!(
        text(&check).contains("kernel-integrity"),
        "{}",
        text(&check)
    );

    // Without a terminal, `init` refuses to re-pin over the drift.
    let refused = sb.moat(&["init", "--yes"]);
    assert_eq!(refused.status.code(), Some(USAGE), "{}", text(&refused));
    assert!(
        text(&refused).contains("openmoat doctor --accept"),
        "{}",
        text(&refused)
    );
    assert_eq!(guard_read_src(&sb)["permissionDecision"], "deny");

    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK),
        "init re-pins"
    );
    assert_eq!(guard_read_src(&sb)["permissionDecision"], "allow");
}

#[cfg(unix)]
#[test]
fn policy_swapped_for_a_symlink_is_denied_even_with_identical_bytes() {
    let sb = sandbox();
    assert_eq!(guard_read_src(&sb)["permissionDecision"], "allow");

    let copy = sb.home.join("elsewhere.yaml");
    std::fs::copy(policy_path(&sb), &copy).unwrap();
    std::fs::remove_file(policy_path(&sb)).unwrap();
    std::os::unix::fs::symlink(&copy, policy_path(&sb)).unwrap();

    let d = guard_read_src(&sb);
    assert_eq!(
        d["permissionDecision"], "deny",
        "a link to the same bytes is still a swap"
    );
    assert_eq!(d["exit"], 2);
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(reason.contains("policy.yaml"), "{reason}");

    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(USAGE));
    assert!(text(&status).contains("policy.yaml"), "{}", text(&status));
}

/// Replacing the directory that holds a pinned file with a link to a copy keeps
/// every leaf name and every byte; the location changed, so it is drift.
#[cfg(unix)]
#[test]
fn directory_of_a_pinned_file_swapped_for_a_symlink_is_denied() {
    let sb = sandbox();
    assert_eq!(guard_read_src(&sb)["permissionDecision"], "allow");

    let claude = sb.home.join(".claude");
    let moved = sb.home.join("claude-original");
    std::fs::rename(&claude, &moved).unwrap();
    let copy = sb.home.join("attacker-claude");
    std::fs::create_dir(&copy).unwrap();
    std::fs::copy(moved.join("settings.json"), copy.join("settings.json")).unwrap();
    std::os::unix::fs::symlink(&copy, &claude).unwrap();

    let d = guard_read_src(&sb);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(reason.contains("settings.json"), "{reason}");
}

#[test]
fn removed_hook_file_is_detected() {
    let sb = sandbox();
    std::fs::remove_file(settings_path(&sb)).unwrap();
    let d = guard_read_src(&sb);
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("settings.json is missing")
    );
}

#[test]
fn doctor_reports_health_drift_and_refuses_to_accept_outside_a_terminal() {
    let sb = sandbox();
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("healthy"), "{}", text(&out));

    let mut policy = std::fs::read_to_string(policy_path(&sb)).unwrap();
    policy.push_str("\n# edited by hand\n");
    std::fs::write(policy_path(&sb), policy).unwrap();
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let report = text(&out);
    assert!(report.contains("✗"), "{report}");
    assert!(report.contains("policy.yaml"), "{report}");
    assert!(report.contains("problem(s)"), "{report}");

    let out = sb.moat(&["doctor", "--accept"]);
    assert_eq!(
        out.status.code(),
        Some(USAGE),
        "stdin is a pipe, so --accept must refuse"
    );
    assert!(text(&out).contains("terminal"), "{}", text(&out));
    assert_eq!(
        guard_read_src(&sb)["permissionDecision"],
        "deny",
        "still denied after the refused accept"
    );

    std::fs::remove_file(sb.home.join(".claude/settings.json")).unwrap();
    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("settings.json"), "{}", text(&out));
}

#[test]
fn doctor_and_accept_name_the_keys_that_changed() {
    let sb = sandbox();
    let mut settings: Value =
        serde_json::from_str(&std::fs::read_to_string(settings_path(&sb)).unwrap()).unwrap();
    settings["hooks"] = Value::Null;
    settings["model"] = Value::from("x");
    settings["theme"] = Value::from("light");
    std::fs::write(settings_path(&sb), settings.to_string()).unwrap();
    // `theme` is not pinned, so it is not named.
    let expected = "settings.json was modified: changed hooks; added model";

    let out = sb.moat(&["doctor"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(text(&out).contains(expected), "{}", text(&out));

    let out = sb.moat_as_person(&["doctor", "--accept"]);
    let report = text(&out);
    let (shown, repinned) = (report.find(expected), report.find("lock re-pinned"));
    assert!(shown.is_some() && shown < repinned, "{report}");
}

#[test]
fn ungoverned_tool_is_denied_while_the_lock_shows_drift() {
    let sb = sandbox();
    let ungoverned = fixture("claude-code/ungoverned.json");
    assert_eq!(sb.guard("claude-code", &ungoverned).status.code(), Some(OK));

    let mut policy = std::fs::read_to_string(policy_path(&sb)).unwrap();
    policy.push_str("\n# tampered by an agent\n");
    std::fs::write(policy_path(&sb), policy).unwrap();

    let out = sb.guard("claude-code", &ungoverned);
    assert_eq!(out.status.code(), Some(DENY));
    let reason = hook_output(&out)["permissionDecisionReason"].to_string();
    assert!(reason.contains("kernel-integrity"), "{reason}");
}

#[test]
fn missing_lock_denies_and_points_to_init() {
    let sb = sandbox();
    std::fs::remove_file(lock_path(&sb)).unwrap();
    let d = guard_read_src(&sb);
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("openmoat init")
    );
}

#[test]
fn status_reports_lock_state() {
    let sb = sandbox();
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("lock"));
    std::fs::write(policy_path(&sb), "version: 1\n").unwrap();
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("was modified"));
}

#[cfg(unix)]
#[test]
fn planted_binary_earlier_on_the_search_path_is_denied() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::common::output;
    let sb = Sandbox::bare(&[".claude"]);
    let dir = tempfile::tempdir().unwrap();
    let home = sb.home.clone();
    let early = dir.path().join("early-bin");
    let real = dir.path().join("real-bin");
    for d in [early.clone(), real.clone()] {
        std::fs::create_dir_all(d).unwrap();
    }
    let script = |p: &Path| {
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script(&real.join("git"));
    let search_path = format!("{}:{}", early.display(), real.display());
    let run = |args: &[&str], stdin: &str| {
        output(
            sb.command().args(args).env("PATH", &search_path),
            Some(stdin),
        )
    };
    assert_eq!(run(&["init", "--yes"], "").status.code(), Some(OK));
    let payload = serde_json::json!({
        "session_id": "pin", "cwd": home.to_string_lossy(), "tool_name": "Bash",
        "tool_input": {"command": "git status --short"}, "tool_use_id": "t"
    })
    .to_string();
    let decision = |out| hook_output(&out);
    assert_eq!(
        decision(run(&["guard", "--host", "claude-code"], &payload))["permissionDecision"],
        "allow"
    );

    script(&early.join("git"));
    let d = decision(run(&["guard", "--host", "claude-code"], &payload));
    assert_eq!(d["permissionDecision"], "deny");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("executables"), "{reason}");
    assert!(reason.contains("early-bin"), "{reason}");
}

/// #158, #298: the hook file an agent reads depends on the agent's
/// `CLAUDE_CONFIG_DIR`. A person re-pinning from a shell with another value must
/// not drop it from the lock, nor quietly adopt the hook file that shell points
/// at: commands follow the directory `init` recorded, and `doctor` reports the
/// variable that disagrees. Only `init` with the variable set moves the record.
#[test]
fn repin_from_another_config_dir_keeps_the_pinned_hook_file() {
    use std::path::Path;

    use crate::common::output;
    let sb = Sandbox::bare(&[]);
    let agent = sb.home.join("agent-claude");
    let shell = sb.home.join("shell-claude");
    let run = |dir: &Path, args: &[&str]| {
        let mut cmd = sb.command();
        cmd.args(args)
            .env("CLAUDE_CONFIG_DIR", dir)
            .env("MOAT_ASSUME_TTY", "1");
        output(&mut cmd, None)
    };
    let pinned = |dir: &Path| {
        let lock: Value =
            serde_json::from_str(&std::fs::read_to_string(lock_path(&sb)).unwrap()).unwrap();
        let suffix = format!(
            "{}/settings.json",
            dir.file_name().unwrap().to_string_lossy()
        );
        lock["entries"]
            .as_object()
            .unwrap()
            .keys()
            .any(|k| k.replace('\\', "/").ends_with(&suffix))
    };
    std::fs::create_dir_all(&agent).unwrap();
    std::fs::create_dir_all(&shell).unwrap();
    assert_eq!(run(&agent, &["init", "--yes"]).status.code(), Some(OK));
    // The other shell's directory holds an OpenMoat hook the lock never pinned.
    std::fs::copy(agent.join("settings.json"), shell.join("settings.json")).unwrap();

    let mut policy = std::fs::read_to_string(policy_path(&sb)).unwrap();
    policy.push_str("\n# edited by the owner\n");
    std::fs::write(policy_path(&sb), policy).unwrap();
    let out = run(&shell, &["doctor", "--accept"]);
    let report = text(&out);
    assert!(report.contains("lock re-pinned"), "{report}");
    assert!(
        pinned(&agent),
        "doctor --accept dropped the agent's hook file"
    );
    assert!(
        !pinned(&shell),
        "doctor --accept adopted an unpinned hook file"
    );
    assert_eq!(out.status.code(), Some(USAGE), "{report}");
    assert!(
        report.contains("CLAUDE_CONFIG_DIR is") && report.contains("which OpenMoat uses"),
        "{report}"
    );
    assert!(
        report.contains("Claude Code      hook installed"),
        "{report}"
    );
    assert!(!report.contains("not pinned"), "{report}");

    let out = run(&shell, &["allow", "npm install left-pad", "--always"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        pinned(&agent),
        "allow --always dropped the agent's hook file"
    );
    assert!(
        !pinned(&shell),
        "allow --always adopted an unpinned hook file"
    );

    for dir in [&shell, &agent] {
        let out = run(dir, &["status"]);
        assert!(!text(&out).contains("not pinned"), "{}", text(&out));
    }

    let settings = std::fs::read_to_string(agent.join("settings.json")).unwrap();
    let settings = settings.replacen('{', r#"{"apiKeyHelper":"x","#, 1);
    std::fs::write(agent.join("settings.json"), settings).unwrap();
    let d = guard_read_src(&sb);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("settings.json was modified"), "{reason}");

    assert_eq!(run(&shell, &["init", "--yes"]).status.code(), Some(OK));
    assert!(pinned(&agent) && pinned(&shell), "init keeps and adopts");
}
