//! Session grants and the permanent allow overlay as seen by `guard`.

use serde_json::Value;

use crate::common::{OK, Sandbox, USAGE, bash_payload, hook_output, text};

/// The hook decision for one Bash call in the sandbox's project.
fn decide(sb: &Sandbox, session: &str, command: &str) -> Value {
    hook_output(&sb.guard(
        "claude-code",
        &bash_payload(session, &sb.project(), command),
    ))
}

/// Write a state file directly, as a person (or an attacker) editing it would.
fn write_state(sb: &Sandbox, relative: &str, contents: &str) {
    let path = sb.home.join(".moat").join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// Milliseconds since the epoch, as `moat` stamps grants.
fn now_ms() -> i64 {
    let since = std::time::UNIX_EPOCH.elapsed().unwrap();
    i64::try_from(since.as_millis()).unwrap()
}

/// `approvals.json` holding one Claude Code grant for session `s1` in the
/// sandbox's project, created at `granted_at_ms` (no timestamp at all when
/// `None`, as files from before expiry).
fn write_grant(sb: &Sandbox, command: &str, granted_at_ms: Option<i64>) {
    // As OpenMoat writes it: links resolved, in slash form, without the
    // verbatim prefix Windows adds.
    let project = std::fs::canonicalize(sb.project()).unwrap();
    let project = project.to_string_lossy();
    let project = project.strip_prefix(r"\\?\").unwrap_or(&project);
    let mut grant = serde_json::json!({"host": "claude-code", "session_id": "s1",
        "action": {"shell": {"command": command}},
        "project": project.replace('\\', "/")});
    if let Some(at) = granted_at_ms {
        grant["granted_at_ms"] = Value::from(at);
    }
    let file = serde_json::json!({"version": 2, "entries": [grant]});
    write_state(sb, "approvals.json", &file.to_string());
}

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[test]
fn session_grants_expire_and_are_pruned_on_write() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let command = "npm install left-pad-pro";
    let mut person = sb.command();
    person.env("MOAT_ASSUME_TTY", "1");

    write_grant(&sb, command, Some(now_ms() - DAY_MS - 60_000));
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK),
        "init re-pins"
    );
    let d = decide(&sb, "s1", command);
    assert_eq!(
        d["permissionDecision"], "ask",
        "a grant older than 24 h: {d}"
    );
    let status = text(&sb.moat(&["status"]));
    assert!(status.contains("no active session grants"), "{status}");

    write_grant(&sb, command, None);
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    let d = decide(&sb, "s1", command);
    assert_eq!(
        d["permissionDecision"], "ask",
        "a grant without a timestamp: {d}"
    );

    write_grant(&sb, command, Some(now_ms() - DAY_MS + 3_600_000));
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    assert_eq!(decide(&sb, "s1", command)["permissionDecision"], "allow");
    let status = text(&sb.moat(&["status"]));
    assert!(
        status.contains("1 active session grant(s), oldest 23h"),
        "{status}"
    );

    // Writing approvals.json drops the expired grants it holds.
    write_grant(&sb, command, Some(now_ms() - 2 * DAY_MS));
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    let out = crate::common::output(
        person.args([
            "allow",
            "ls -la",
            "--host",
            "claude-code",
            "--session",
            "s2",
        ]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let file = std::fs::read_to_string(sb.home.join(".moat/approvals.json")).unwrap();
    assert!(!file.contains(command), "expired grant kept: {file}");
    assert!(file.contains("ls -la"), "{file}");
}

#[test]
fn init_pins_grants_and_overlay() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let lock: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    let keys: Vec<&str> = lock["entries"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        keys.iter().any(|k| k.ends_with("approvals.json")),
        "{keys:?}"
    );
    assert!(
        keys.iter().any(|k| k.ends_with("approved.yaml")),
        "{keys:?}"
    );
}

#[test]
fn session_grant_turns_ask_into_allow_for_that_session_only() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(
        decide(&sb, "s1", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );

    write_grant(&sb, "npm install left-pad-pro", Some(now_ms()));
    let tampered = decide(&sb, "s1", "npm install left-pad-pro");
    assert_eq!(
        tampered["permissionDecision"], "deny",
        "edited grants break the lock"
    );
    assert!(
        tampered["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("kernel-integrity")
    );

    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK),
        "init re-pins"
    );
    let granted = decide(&sb, "s1", "npm install left-pad-pro");
    assert_eq!(granted["permissionDecision"], "allow", "{granted}");
    assert!(
        granted["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-session")
    );
    assert_eq!(
        decide(&sb, "s2", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        decide(&sb, "s1", "npm install left-pad-pro --save-dev")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        decide(&sb, "s1", "cat ~/.ssh/id_rsa")["permissionDecision"],
        "deny",
        "grants never beat deny"
    );
}

#[test]
fn permanent_overlay_rules_merge_into_the_policy() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    write_state(
        &sb,
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: approved-1\n    reason: test\n    shell: ['pip install requests']\n",
    );
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    let d = decide(&sb, "any", "pip install requests");
    assert_eq!(d["permissionDecision"], "allow", "{d}");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-1")
    );

    write_state(
        &sb,
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: evil\n    shell: ['*']\n",
    );
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    let d = decide(&sb, "any", "terraform apply");
    assert_eq!(
        d["permissionDecision"], "deny",
        "a malformed overlay fails closed: {d}"
    );
}

#[test]
fn allow_requires_a_terminal() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let out = sb.moat(&["allow", "npm install x", "--always"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("must be run by a person in a terminal"));
    assert!(
        !sb.home.join(".moat/policy.d/approved.yaml").exists()
            || std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml"))
                .unwrap()
                .contains("allow: []")
    );
}

#[test]
fn a_command_grant_from_an_earlier_release_stops_applying_and_status_names_it() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let command = "npm install left-pad-pro";
    // As an earlier release wrote it: no project.
    let grant = serde_json::json!({"host": "claude-code", "session_id": "s1",
        "action": {"shell": {"command": command}}, "granted_at_ms": now_ms()});
    let file = serde_json::json!({"version": 2, "entries": [grant]});
    write_state(&sb, "approvals.json", &file.to_string());
    assert_eq!(
        sb.moat_as_person(&["init", "--yes"]).status.code(),
        Some(OK)
    );
    let d = decide(&sb, "s1", command);
    assert_eq!(d["permissionDecision"], "ask", "{d}");
    let status = text(&sb.moat(&["status"]));
    assert!(
        status.contains("needs approving again: it names no project"),
        "{status}"
    );
    let listed = text(&sb.moat(&["allowed"]));
    assert!(listed.contains("applies nowhere"), "{listed}");
}
