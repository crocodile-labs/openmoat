//! A person answering a taint ask once for the rest of the session: `moat allow`
//! after the session read untrusted content, or their answer in the agent to a
//! write of the same file (ADR-048). The attack side of the same changes: a
//! grant from before the taint, another file, another session, a secret the
//! session read, a declined write and a write that changed nothing are not
//! answered.

use serde_json::json;

use crate::common::{OK, Sandbox, text};
use crate::taint::{call, decide};

/// Fetched content taints `s1`; a write of `file` there.
fn tainted_write(sb: &Sandbox, session: &str, file: &str) -> (String, String) {
    tainted_write_of(sb, session, file, "x")
}

/// A `Write` of `content` to `file` in the project by `session`.
fn tainted_write_of(sb: &Sandbox, session: &str, file: &str, content: &str) -> (String, String) {
    let proj = sb.project();
    let input = json!({"file_path": proj.join(file).to_string_lossy(), "content": content});
    decide(sb, "claude-code", &call(session, &proj, "Write", &input))
}

/// An `Edit` of `file` in the project by `session`, replacing `old` with `new`.
fn tainted_edit(sb: &Sandbox, session: &str, file: &str, old: &str, new: &str) -> (String, String) {
    let proj = sb.project();
    let input = json!({
        "file_path": proj.join(file).to_string_lossy(), "old_string": old, "new_string": new
    });
    decide(sb, "claude-code", &call(session, &proj, "Edit", &input))
}

/// The agent writes `content` to `file`, as the host does once the person approves.
fn approved(sb: &Sandbox, file: &str, content: &str) {
    std::fs::write(sb.project().join(file), content).unwrap();
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
        reason.contains("openmoat allow --last"),
        "the ask says how: {reason}"
    );

    let out = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let (verdict, reason) = tainted_write(&sb, "s1", "CMakeLists.txt");
    assert_eq!(verdict, "allow", "{reason}");
    assert!(
        reason.contains("after the session last read untrusted content"),
        "{reason}"
    );

    // More untrusted content after the grant: the grant did not see it, so the
    // same file asks again until it is answered again.
    fetch_untrusted(&sb, "s1");
    let (verdict, reason) = tainted_write(&sb, "s1", "CMakeLists.txt");
    assert_eq!(verdict, "ask", "a later read asks again: {reason}");
    let out = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(tainted_write(&sb, "s1", "CMakeLists.txt").0, "allow");

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
    let out = sb.moat_approving(&["allow", "--last"]);
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
         allow:\n  - id: registries\n    net: [api.github.com, crates.io]\n\
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
    let out = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (verdict, reason) = send();
    assert_eq!(verdict, "ask", "{reason}");
    assert!(
        reason.contains("[session-taint]") && reason.contains(".ssh/id_rsa"),
        "{reason}"
    );
}

/// The person's answer in the agent covers the file (ADR-048): once the file
/// holds what an asked write sent (and did not before), later writes of it in
/// the session are allowed, until the session reads untrusted content again.
/// The attack side: a declined write leaves no such file, so its retry asks;
/// another file and another session ask; and a later untrusted read asks once
/// more, answered again only by a write the person let run after it.
#[test]
fn an_approved_write_in_the_agent_covers_later_writes_of_the_same_file() {
    let sb = Sandbox::installed(&[".claude"]);
    let file = "CMakeLists.txt";
    fetch_untrusted(&sb, "s1");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "x");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("session-taint"), "{reason}");

    // Declined: the file was not written, so the same write asks again.
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "x");
    assert_eq!(verdict, "ask", "a declined write covers nothing: {reason}");

    // Approved: the agent writes the file; the next write of it is covered.
    approved(&sb, file, "x");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "y");
    assert_eq!(verdict, "allow", "{reason}");
    assert!(
        reason.contains("an earlier write of") && reason.contains(file),
        "{reason}"
    );
    assert!(!reason.contains("[session-taint]"), "{reason}");

    // Only that file, only that session.
    let (verdict, reason) = tainted_write(&sb, "s1", "pom.xml");
    assert_eq!(verdict, "ask", "another file still asks: {reason}");
    fetch_untrusted(&sb, "s2");
    let (verdict, reason) = tainted_write_of(&sb, "s2", file, "y");
    assert_eq!(verdict, "ask", "another session still asks: {reason}");

    // More untrusted content: the answer did not see it, so the file asks once
    // more; a write the person then lets run answers again.
    fetch_untrusted(&sb, "s1");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "y");
    assert_eq!(verdict, "ask", "a later read asks again: {reason}");
    approved(&sb, file, "y");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "z");
    assert_eq!(verdict, "allow", "{reason}");
}

/// No evidence of an approval: a write of what the file already holds (a probe
/// the person may well have declined) covers nothing.
#[test]
fn a_write_that_changed_nothing_does_not_cover_the_file() {
    let sb = Sandbox::installed(&[".claude"]);
    let file = "CMakeLists.txt";
    approved(&sb, file, "x");
    fetch_untrusted(&sb, "s1");

    // The file holds `x` already: this write asks, and whether the person
    // approved or declined it the file looks the same.
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "x");
    assert_eq!(verdict, "ask", "{reason}");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "evil");
    assert_eq!(verdict, "ask", "a probe is no approval: {reason}");
    assert!(reason.contains("session-taint"), "{reason}");
}

/// An `Edit` is covered like a `Write` (ADR-048): the hook works out the content
/// the edit leaves from the file as it is, and once the file holds it the next
/// edit or write of the file is allowed. A declined edit covers nothing, an
/// edit Claude Code would refuse (`old_string` twice) covers nothing, and
/// `MultiEdit` is read the same way.
#[test]
fn an_approved_edit_in_the_agent_covers_later_edits_of_the_same_file() {
    let sb = Sandbox::installed(&[".claude"]);
    let file = "CMakeLists.txt";
    approved(&sb, file, "project(a)\nadd_executable(a a.c)\n");
    fetch_untrusted(&sb, "s1");

    let (verdict, reason) = tainted_edit(&sb, "s1", file, "project(a)", "project(b)");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("session-taint"), "{reason}");
    // declined: the file is as it was, so the same edit asks again
    let (verdict, reason) = tainted_edit(&sb, "s1", file, "project(a)", "project(b)");
    assert_eq!(verdict, "ask", "a declined edit covers nothing: {reason}");

    // approved: the agent's edit ran
    approved(&sb, file, "project(b)\nadd_executable(a a.c)\n");
    let (verdict, reason) = tainted_edit(&sb, "s1", file, "a.c", "b.c");
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("an earlier write of"), "{reason}");
    // the allowed edit ran: the file holds what it left, which the next call's
    // check compares against (an edit the agent never applied covers nothing)
    approved(&sb, file, "project(b)\nadd_executable(a b.c)\n");
    let (verdict, reason) = tainted_write_of(&sb, "s1", file, "project(c)\n");
    assert_eq!(
        verdict, "allow",
        "a write of the file is covered too: {reason}"
    );
    approved(&sb, file, "project(c)\n");

    // `MultiEdit`, approved, covers as well
    fetch_untrusted(&sb, "s1");
    let proj = sb.project();
    let multi = json!({"file_path": proj.join(file).to_string_lossy(), "edits": [
        {"old_string": "project", "new_string": "library"},
        {"old_string": "(c)", "new_string": "(c, d)", "replace_all": true}
    ]});
    let (verdict, reason) = decide(&sb, "claude-code", &call("s1", &proj, "MultiEdit", &multi));
    assert_eq!(verdict, "ask", "a later read asks again: {reason}");
    approved(&sb, file, "library(c, d)\n");
    let (verdict, reason) = tainted_edit(&sb, "s1", file, "library", "module");
    assert_eq!(verdict, "allow", "{reason}");

    // `old_string` twice without `replace_all`: Claude Code refuses the edit,
    // so what it would leave is not known, whatever the file holds afterwards
    fetch_untrusted(&sb, "s1");
    approved(&sb, file, "x\nx\n");
    let (verdict, reason) = tainted_edit(&sb, "s1", file, "x", "y");
    assert_eq!(verdict, "ask", "{reason}");
    approved(&sb, file, "y\nx\n");
    let (verdict, reason) = tainted_edit(&sb, "s1", file, "x", "z");
    assert_eq!(
        verdict, "ask",
        "an edit that would be refused covers nothing: {reason}"
    );
}

/// `moat allow --last` answering `s` on a taint ask.
fn allow_last_answering(sb: &Sandbox, answer: &str) -> std::process::Output {
    crate::common::output(
        sb.command()
            .args(["allow", "--last"])
            .env("MOAT_ASSUME_TTY", "1"),
        Some(answer),
    )
}

/// Answering `s` approves every protected write of the session until it reads
/// untrusted content again. The attack side: a later read takes it back,
/// another session still asks, and `s` approves nothing on an ask that is not
/// a taint ask.
#[test]
fn answering_s_covers_the_sessions_protected_writes_until_the_next_untrusted_read() {
    let sb = Sandbox::installed(&[".claude"]);
    fetch_untrusted(&sb, "s1");
    assert_eq!(tainted_write(&sb, "s1", "CMakeLists.txt").0, "ask");
    let out = allow_last_answering(&sb, "s\n");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("[y/s/N]"), "{}", text(&out));
    assert!(
        text(&out).contains("every protected write"),
        "{}",
        text(&out)
    );

    // The asked file has its own grant; the others are covered by `s`.
    assert_eq!(tainted_write(&sb, "s1", "CMakeLists.txt").0, "allow");
    // `.claude/agents/` asks on its own now (`runs-later`), so `s` cannot cover it.
    for file in ["pom.xml", "Makefile"] {
        let (verdict, reason) = tainted_write(&sb, "s1", file);
        assert_eq!(verdict, "allow", "{file}: {reason}");
        assert!(
            reason.contains("protected writes were approved"),
            "{reason}"
        );
    }

    fetch_untrusted(&sb, "s1");
    let (verdict, reason) = tainted_write(&sb, "s1", "pom.xml");
    assert_eq!(verdict, "ask", "a later read takes it back: {reason}");

    fetch_untrusted(&sb, "s2");
    let (verdict, reason) = tainted_write(&sb, "s2", "pom.xml");
    assert_eq!(verdict, "ask", "another session still asks: {reason}");

    // A clean session's workflow write asks (`runs-later`), not a taint ask:
    // `s` is not offered there and approves nothing.
    assert_eq!(
        tainted_write(&sb, "s3", ".github/workflows/ci.yml").0,
        "ask"
    );
    let out = allow_last_answering(&sb, "s\n");
    assert!(text(&out).contains("nothing approved"), "{}", text(&out));
    assert_eq!(
        tainted_write(&sb, "s3", ".github/workflows/ci.yml").0,
        "ask"
    );
}
