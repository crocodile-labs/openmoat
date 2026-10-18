//! `moat allow --last` for file actions: a session grant for the exact files an
//! ask named, or with `--always` a permanent rule for exactly those paths.

use std::path::Path;

use crate::common::{DENY, OK, Sandbox, hook_output, stderr, text, verdict};

fn patch(sb: &Sandbox, file: &str) -> String {
    serde_json::json!({
        "session_id": "codex-s1", "turn_id": "t-1", "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_use_id": "call-1",
        "tool_input": {"command": format!(
            "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-a\n+b\n*** Add File: {file}\n+x\n*** End Patch\n"
        )},
    })
    .to_string()
}

fn read(sb: &Sandbox, session: &str, path: &Path) -> String {
    serde_json::json!({
        "session_id": session, "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": path.to_string_lossy()}, "tool_use_id": "t1"
    })
    .to_string()
}

/// Codex cannot ask, so a patch that writes outside the project is denied with
/// how to approve it; `moat allow --last` grants that exact patch to the session.
#[test]
fn codex_apply_patch_ask_is_approved_with_allow_last() {
    let sb = Sandbox::installed_asking(&[".codex"]);
    let out = sb.guard("codex", &patch(&sb, "../notes/plan.md"));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    let reason = hook_output(&out)["permissionDecisionReason"].to_string();
    assert!(reason.contains("run `moat`"), "{reason}");
    assert!(reason.contains("moat allow --last"), "{reason}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
    let shown = text(&allow);
    assert!(
        shown.contains("session codex-s1 on codex may write"),
        "{shown}"
    );
    assert!(shown.contains("notes/plan.md"), "{shown}");
    assert_eq!(
        verdict(&sb.guard("codex", &patch(&sb, "../notes/plan.md"))),
        "allow"
    );
    assert_eq!(
        verdict(&sb.guard("codex", &patch(&sb, "../notes/other.md"))),
        "deny",
        "only the approved files"
    );
}

/// `--always` writes an `fs.read` rule for exactly the asked path and prints how
/// to take it back; it then applies to every session, and to that path only.
#[test]
fn claude_code_read_ask_is_approved_for_good() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let notes = sb.home.join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::write(notes.join("plan.md"), "plan").unwrap();
    let plan = read(&sb, "s1", &notes.join("plan.md"));
    assert_eq!(verdict(&sb.guard("claude-code", &plan)), "ask");

    let allow = sb.moat_approving(&["allow", "--last", "--always"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
    let shown = text(&allow);
    assert!(shown.contains("wanted to read"), "{shown}");
    assert!(shown.contains("fs.read"), "{shown}");
    assert!(
        shown.contains("will allow: read exactly ")
            && shown.contains("plan.md (no other path); deny rules still win"),
        "{shown}"
    );
    assert!(
        shown.contains("undo: moat allow --remove approved-1"),
        "{shown}"
    );
    assert!(shown.contains("moat allow --dir"), "{shown}");
    let rules = std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml")).unwrap();
    assert!(rules.contains("plan.md") && !rules.contains('*'), "{rules}");

    let later = read(&sb, "s2", &notes.join("plan.md"));
    assert_eq!(verdict(&sb.guard("claude-code", &later)), "allow");
    let other = read(&sb, "s2", &notes.join("other.md"));
    assert_eq!(verdict(&sb.guard("claude-code", &other)), "ask");
}

/// Deny rules still win over an approved path: once it leads into `~/.ssh`, the
/// read is denied although a permanent rule names it.
#[cfg(unix)]
#[test]
fn an_approved_path_that_leads_into_ssh_is_still_denied() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let ssh = sb.home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_rsa"), "key").unwrap();
    let key = sb.home.join("key");
    std::fs::write(&key, "not yet").unwrap();
    assert_eq!(
        verdict(&sb.guard("claude-code", &read(&sb, "s1", &key))),
        "ask"
    );
    let allow = sb.moat_approving(&["allow", "--last", "--always"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", text(&allow));
    assert_eq!(
        verdict(&sb.guard("claude-code", &read(&sb, "s1", &key))),
        "allow"
    );

    std::fs::remove_file(&key).unwrap();
    std::os::unix::fs::symlink(ssh.join("id_rsa"), &key).unwrap();
    let out = sb.guard("claude-code", &read(&sb, "s1", &key));
    let reason = hook_output(&out)["permissionDecisionReason"].to_string();
    assert_eq!(out.status.code(), Some(DENY), "{reason}");
    assert!(reason.contains("secrets-paths"), "{reason}");
}
