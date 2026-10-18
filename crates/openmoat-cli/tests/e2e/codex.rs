//! Codex: its `PreToolUse` cannot ask, so an `ask` must still stop the call.

use crate::common::{DENY, OK, Sandbox, fixture, hook_output, stderr, stdout};

fn shell(session: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session,
        "turn_id": "t-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "call-1",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// Codex rejects `permissionDecision: "ask"` as unsupported and then runs the
/// call. An `ask` must therefore reach Codex as a blocking `deny` (exit 2) that
/// tells the person how to approve it, while the audit log keeps the `ask` so
/// `moat allow --last` can turn it into a session grant.
#[test]
fn an_ask_blocks_codex_until_a_person_approves_it() {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".codex")).unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));

    // still an `ask` under ADR-025: a pager is a program git runs later
    let command = "git config core.pager less";
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    let d = hook_output(&out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("[git-internals]"), "{reason}");
    assert!(reason.contains("moat allow --last"), "{reason}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(OK), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // Claude Code can ask, so it still receives the `ask` itself.
    let claude = serde_json::json!({
        "session_id": "s-claude", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": command }, "tool_use_id": "t1"
    });
    let out = sb.guard("claude-code", &claude.to_string());
    assert_eq!(out.status.code(), Some(OK));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");

    // A call no rule matches is left to Codex's own approval policy (ADR-025):
    // no output, exit 0, and never the blocking deny an `ask` becomes.
    let out = sb.guard("codex", &shell("codex-s2", "npm install left-pad"));
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", stdout(&out));
}

/// Codex runs `PermissionRequest` hooks only once it has decided to prompt, so
/// that event cannot carry an `ask` from `PreToolUse` (#178) and `moat init` does
/// not install it. If a person wires `guard` to it anyway, `guard` refuses the
/// event, even for a command it would allow: exit 2 with a reason on stderr,
/// which Codex reads as a deny, never as an approval.
#[test]
fn a_codex_permission_request_is_refused_never_approved() {
    let sb = Sandbox::installed(&[".codex"]);
    let out = sb.guard("codex", &fixture("codex/permission-request-shell.json"));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    assert!(stderr(&out).contains("moat: deny"), "{}", stderr(&out));
}
