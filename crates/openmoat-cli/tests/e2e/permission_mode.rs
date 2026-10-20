//! Claude Code permission modes that put no question to a person.

use crate::common::{DENY, OK, Sandbox, hook_output, stderr, stdout};

fn bash(sb: &Sandbox, session: &str, mode: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session, "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": command }, "tool_use_id": "t1",
        "permission_mode": mode,
    })
    .to_string()
}

/// In `bypassPermissions` an `ask` would run unseen, so it reaches Claude Code
/// as a blocking deny with the way to approve it; the audit log keeps the
/// `ask`, so `moat allow --last` finds it. A `defer` stays a defer.
#[test]
fn an_ask_under_bypass_permissions_is_a_deny_a_person_can_approve() {
    let sb = Sandbox::installed(&[".claude"]);
    // an `ask` under the default policy: a pager is a program git runs later
    let command = "git config core.pager less";
    let out = sb.guard(
        "claude-code",
        &bash(&sb, "s1", "bypassPermissions", command),
    );
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    let d = hook_output(&out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("openmoat allow --last"), "{reason}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = sb.guard(
        "claude-code",
        &bash(&sb, "s1", "bypassPermissions", command),
    );
    assert_eq!(out.status.code(), Some(OK), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // In a mode that prompts, the `ask` is Claude Code's to put to the person.
    let out = sb.guard("claude-code", &bash(&sb, "s2", "default", command));
    assert_eq!(out.status.code(), Some(OK));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");

    // A call no rule matches is left to Claude Code, whatever its mode.
    let out = sb.guard(
        "claude-code",
        &bash(&sb, "s3", "bypassPermissions", "npm install left-pad"),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", stdout(&out));
}
