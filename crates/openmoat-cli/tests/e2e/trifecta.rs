//! The lethal trifecta and argument conditions (ADR-113) through the real
//! binary: the session's facts read back from the audit log, an MCP call's
//! arguments read from the hook payload.

use serde_json::json;

use crate::common::{OK, Sandbox, text};
use crate::hosts::dir_of;
use crate::taint::{call, decide};
use openmoat_hosts::Host;

/// `policy` installed and re-pinned by a person, as the session-taint tests do.
fn with_policy(policy: &str) -> Sandbox {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    std::fs::write(sb.home.join(".moat/policy.yaml"), policy).unwrap();
    let accept = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accept).contains("re-pinned"), "{}", text(&accept));
    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    sb
}

// coverage: ASI01, ASI02
#[test]
fn issue_text_and_an_agent_login_make_a_later_push_need_review() {
    // An agent's login file, under the agent's directory from its spec.
    let login_file = format!("{}/auth.json", dir_of(Host::Codex));
    let sb = with_policy(&format!(
        "version: 1\ndefaults: {{ '*': review, net: deny }}\n\
         allow:\n  - id: dev\n    shell: ['gh issue view *', 'git push *']\n\
         \x20 - id: registries\n    net: [api.github.com, github.com]\n\
         review:\n  - id: agent-credentials\n    fs.read: ['~/{login_file}']\n",
    ));
    let proj = sb.project();
    let bash = |session, command: &str| {
        let input = json!({ "command": command });
        decide(
            &sb,
            Host::ClaudeCode.id(),
            &call(session, &proj, "Bash", &input),
        )
    };
    assert_eq!(bash("s1", "gh issue view 7 --comments").0, "allow");
    let login = json!({"file_path": sb.home.join(&login_file).to_string_lossy()});
    let (verdict, reason) = decide(
        &sb,
        Host::ClaudeCode.id(),
        &call("s1", &proj, "Read", &login),
    );
    assert_eq!(verdict, "ask", "{reason}");

    let (verdict, reason) = bash("s1", "git push origin main");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("[lethal-trifecta]"), "{reason}");
    assert!(reason.contains(&login_file), "{reason}");
    assert!(reason.contains("gh issue view 7"), "{reason}");
    // another session that read neither pushes as before
    assert_eq!(bash("s2", "git push origin main").0, "allow");
}

// coverage: ASI02
#[test]
fn an_mcp_send_to_a_recipient_outside_the_list_is_denied() {
    let sb = with_policy(
        "version: 1\ndefaults: { '*': defer, net: deny }\n\
         deny:\n  - id: mail-outside-team\n    reason: sends mail to a recipient outside the team\n\
         \x20   mcp: ['mcp__mail__send_email']\n    when:\n\
         \x20     - { arg: [to, cc, bcc], not_in: ['*@example.com'] }\n",
    );
    let proj = sb.project();
    let send = |to: &str| {
        let input = json!({ "to": to, "subject": "q3" });
        decide(
            &sb,
            Host::ClaudeCode.id(),
            &call("m1", &proj, "mcp__mail__send_email", &input),
        )
    };
    let (verdict, reason) = send("boss@example.com, drop@evil.example");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("[mail-outside-team]"), "{reason}");
    assert!(reason.contains("drop@evil.example"), "{reason}");
    assert_eq!(
        send("boss@example.com").0,
        "defer",
        "inside the list: the host decides"
    );
}
