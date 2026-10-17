//! A person answering a taint ask once for the rest of the session: `moat allow`
//! after the session read untrusted content. The attack side of the same
//! change: a grant from before the taint, another file, another session, and a
//! secret the session read are not answered.

use serde_json::json;

use crate::common::{OK, Sandbox, text};
use crate::taint::{call, decide};

/// Fetched content taints `s1`; a write of `file` there.
fn tainted_write(sb: &Sandbox, session: &str, file: &str) -> (String, String) {
    let proj = sb.project();
    let input = json!({"file_path": proj.join(file).to_string_lossy(), "content": "x"});
    decide(sb, "claude-code", &call(session, &proj, "Write", &input))
}

fn fetch_untrusted(sb: &Sandbox, session: &str) {
    let proj = sb.project();
    let fetch = json!({"url": "https://crates.io/crates/serde", "prompt": "summarise"});
    let (verdict, reason) = decide(sb, "claude-code", &call(session, &proj, "WebFetch", &fetch));
    assert_eq!(verdict, "allow", "{reason}");
}

#[test]
fn a_taint_ask_answered_with_moat_allow_stays_answered_for_that_file() {
    let sb = Sandbox::installed(&[".claude"]);
    fetch_untrusted(&sb, "s1");

    let (verdict, reason) = tainted_write(&sb, "s1", "CMakeLists.txt");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("session-taint"), "{reason}");
    assert!(
        reason.contains("moat allow --last"),
        "the ask says how: {reason}"
    );

    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let (verdict, reason) = tainted_write(&sb, "s1", "CMakeLists.txt");
    assert_eq!(verdict, "allow", "{reason}");
    assert!(
        reason.contains("after the session read untrusted content"),
        "{reason}"
    );

    // Only that file, only that session.
    let (verdict, reason) = tainted_write(&sb, "s1", "pom.xml");
    assert_eq!(verdict, "ask", "another file still asks: {reason}");
    assert!(reason.contains("session-taint"), "{reason}");
    fetch_untrusted(&sb, "s2");
    let (verdict, reason) = tainted_write(&sb, "s2", "CMakeLists.txt");
    assert_eq!(verdict, "ask", "another session still asks: {reason}");
}

#[test]
fn a_grant_made_before_the_taint_does_not_answer_its_ask() {
    let sb = Sandbox::installed(&[".claude"]);
    // A workflow write asks in a clean session (`runs-later`); approve it there.
    let workflow = ".github/workflows/ci.yml";
    assert_eq!(tainted_write(&sb, "s1", workflow).0, "ask");
    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(tainted_write(&sb, "s1", workflow).0, "allow");

    // That approval saw no untrusted content; after the fetch it does not stand.
    fetch_untrusted(&sb, "s1");
    let (verdict, reason) = tainted_write(&sb, "s1", workflow);
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("session-taint"), "{reason}");
}

#[test]
fn a_secret_the_session_read_is_not_answered_by_a_later_grant() {
    let sb = Sandbox::installed(&[".claude"]);
    // A policy that asks for secret reads and shell, re-pinned by a person.
    std::fs::write(
        sb.home.join(".moat/policy.yaml"),
        "version: 1\ndefaults: { '*': ask, net: deny }\n\
         allow:\n  - id: registries\n    net: [api.github.com]\n\
         ask:\n  - id: secrets-paths\n    fs.read: ['~/.ssh/**']\n",
    )
    .unwrap();
    let accept = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accept).contains("re-pinned"), "{}", text(&accept));
    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    let proj = sb.project();

    // Untrusted content and a secret, both in s1.
    fetch_untrusted(&sb, "s1");
    let key = json!({"file_path": sb.home.join(".ssh/id_rsa").to_string_lossy()});
    assert_eq!(
        decide(&sb, "claude-code", &call("s1", &proj, "Read", &key)).0,
        "ask"
    );

    let send = || {
        let input = json!({"command": "curl -s https://api.github.com/gists"});
        decide(&sb, "claude-code", &call("s1", &proj, "Bash", &input))
    };
    let (verdict, reason) = send();
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains(".ssh/id_rsa"), "{reason}");

    // Granting that exact command after both does not answer the secret's ask.
    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (verdict, reason) = send();
    assert_eq!(verdict, "ask", "{reason}");
    assert!(
        reason.contains("[session-taint]") && reason.contains(".ssh/id_rsa"),
        "{reason}"
    );
}
