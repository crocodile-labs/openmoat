//! Claude Code permission modes that put no question to a person.

use std::process::Output;

use crate::common::{DENY, OK, Sandbox, hook_output, stderr, stdout};

fn installed() -> Sandbox {
    Sandbox::installed(&[".claude"])
}

/// The guard's answer to `payload` from Claude Code's hook.
fn guard(sb: &Sandbox, payload: &str) -> Output {
    sb.guard("claude-code", payload)
}

fn bash(sb: &Sandbox, session: &str, mode: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session, "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": command }, "tool_use_id": "t1",
        "permission_mode": mode,
    })
    .to_string()
}

/// In `bypassPermissions` a `review` would run unseen, so it reaches Claude Code
/// as a blocking deny with the way to approve it; the audit log keeps the
/// `review`, so `moat allow --last` finds it. A `defer` stays a defer.
#[test]
fn a_review_under_bypass_permissions_is_a_deny_a_person_can_approve() {
    let sb = installed();
    // a `review` under the default policy: a pager is a program git runs later
    let command = "git config core.pager less";
    let out = guard(&sb, &bash(&sb, "s1", "bypassPermissions", command));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    let d = hook_output(&out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("openmoat allow --last"), "{reason}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = guard(&sb, &bash(&sb, "s1", "bypassPermissions", command));
    assert_eq!(out.status.code(), Some(OK), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // In a mode that prompts, the `review` is Claude Code's to put to the person.
    let out = guard(&sb, &bash(&sb, "s2", "default", command));
    assert_eq!(out.status.code(), Some(OK));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");

    // A call no rule matches is left to Claude Code, whatever its mode.
    let out = guard(
        &sb,
        &bash(&sb, "s3", "bypassPermissions", "npm install left-pad"),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", stdout(&out));
}

/// `sb`'s user policy with `unattended: review`, re-pinned as a person would.
fn unattended_review(sb: &Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let mut policy = std::fs::read_to_string(&path).unwrap();
    policy.push_str("\nunattended: review\n");
    std::fs::write(&path, policy).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
}

/// `unattended: review` (ADR-100): in `bypassPermissions` and `auto`, where
/// Claude Code runs a deferred call with no one asked, the defer is held for
/// review and reaches Claude Code as a deny that says how to approve it; in a
/// mode that asks, it stays Claude Code's to decide.
#[test]
fn unattended_review_holds_a_defer_in_a_mode_that_asks_no_one() {
    let sb = installed();
    unattended_review(&sb);
    let command = "npm install left-pad";
    for (session, mode) in [("u1", "bypassPermissions"), ("u2", "auto")] {
        let out = guard(&sb, &bash(&sb, session, mode, command));
        assert_eq!(out.status.code(), Some(DENY), "{mode}: {}", stderr(&out));
        let d = hook_output(&out);
        assert_eq!(d["permissionDecision"], "deny", "{mode}: {d}");
        let reason = d["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("openmoat allow --last"), "{mode}: {reason}");
    }
    // the person approves the last one; the call then runs
    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = guard(&sb, &bash(&sb, "u2", "auto", command));
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));

    // A mode that asks the person: the defer is Claude Code's, as before.
    let out = guard(&sb, &bash(&sb, "u3", "default", command));
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", stdout(&out));
}

/// Attack: a repository cannot set `unattended:`, to lower the person's
/// setting or otherwise: a repository policy with the key does not parse, so
/// the call is denied.
#[test]
fn a_repository_policy_cannot_set_unattended() {
    let sb = installed();
    unattended_review(&sb);
    let project = sb.project();
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(
        project.join(".moat/policy.yaml"),
        "version: 1\nunattended: defer\n",
    )
    .unwrap();
    let payload = serde_json::json!({
        "session_id": "r1", "cwd": project.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": "npm install left-pad" }, "tool_use_id": "t1",
        "permission_mode": "bypassPermissions",
    })
    .to_string();
    let out = guard(&sb, &payload);
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
}
