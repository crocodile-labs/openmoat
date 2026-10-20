//! `moat` with no subcommand: health, then drift and asks answered at a terminal.

use std::fs;

use crate::common::{OK, Sandbox, USAGE, bash_payload, hook_output, output, text};

const INSTALL: &str = "npm install left-pad";

/// `moat` alone as a person at a terminal, typing `answers`.
fn home_as_person(sb: &Sandbox, answers: &str) -> String {
    let out = output(sb.command().env("MOAT_ASSUME_TTY", "1"), Some(answers));
    text(&out)
}

fn verdict(sb: &Sandbox, session: &str) -> String {
    let payload = bash_payload(session, &sb.project(), INSTALL);
    crate::common::verdict(&sb.guard("claude-code", &payload))
}

fn edit_policy(sb: &Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let mut policy = fs::read_to_string(&path).unwrap();
    policy.push_str("\n# edited by hand\n");
    fs::write(path, policy).unwrap();
}

fn lock(sb: &Sandbox) -> String {
    fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap()
}

#[test]
fn nothing_needs_a_person() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let out = output(&mut sb.command(), Some(""));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("Protecting Claude Code"), "{shown}");
    assert!(shown.contains("today: 0 decisions"), "{shown}");
    assert!(shown.contains("Nothing needs you."), "{shown}");
}

#[test]
fn drift_accepted_with_y_repins() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    edit_policy(&sb);
    let shown = home_as_person(&sb, "y\n");
    assert!(shown.contains("policy.yaml"), "{shown}");
    assert!(shown.contains("Accept these changes? [y/N]"), "{shown}");
    assert!(shown.contains("lock re-pinned"), "{shown}");
    assert!(shown.contains("Nothing needs you."), "{shown}");
    assert!(text(&sb.moat(&["doctor"])).contains("healthy"));
}

#[test]
fn drift_declined_changes_nothing() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    edit_policy(&sb);
    let before = lock(&sb);
    let shown = home_as_person(&sb, "n\n");
    assert!(shown.contains("openmoat doctor"), "{shown}");
    assert!(!shown.contains("re-pinned"), "{shown}");
    assert_eq!(lock(&sb), before);
}

#[test]
fn ask_allowed_once_grants_the_session() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(verdict(&sb, "s1"), "ask");
    let shown = home_as_person(&sb, "o\n");
    assert!(
        shown.contains(&format!("Claude Code asked to run \"{INSTALL}\"")),
        "{shown}"
    );
    assert!(
        shown.contains("session s1 on claude-code may run"),
        "{shown}"
    );
    assert!(shown.contains("`claude --continue` resumes"), "{shown}");
    assert_eq!(verdict(&sb, "s1"), "allow");
    assert_eq!(verdict(&sb, "s2"), "ask", "grants are per session");
    // Answered: s2's ask is the newest now, so it is the one shown.
    assert!(home_as_person(&sb, "n\n").contains("session s2"));
}

/// `[a]lways` says what the permanent rule will match before writing it: a shell
/// rule also matches extra arguments, a file rule only the exact path.
#[test]
fn ask_allowed_always_shows_what_the_rule_matches() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(verdict(&sb, "s1"), "ask");
    let shown = home_as_person(&sb, "a\n");
    assert!(
        shown.contains(&format!(
            "will allow: {INSTALL} (and the same command with extra arguments); \
             deny rules still win"
        )),
        "{shown}"
    );
    assert!(
        shown.contains("undo: openmoat allow --remove approved-1"),
        "{shown}"
    );
    assert_eq!(verdict(&sb, "s2"), "allow");

    let payload = serde_json::json!({
        "session_id": "s3", "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": sb.home.join("notes.md").to_string_lossy()},
        "tool_use_id": "t1"
    })
    .to_string();
    sb.guard("claude-code", &payload);
    let shown = home_as_person(&sb, "a\n");
    assert!(
        shown.contains("will allow: read exactly ")
            && shown.contains("notes.md (no other path); deny rules still win"),
        "{shown}"
    );
    assert!(
        shown.contains("undo: openmoat allow --remove approved-2"),
        "{shown}"
    );
}

#[test]
fn without_a_terminal_nothing_changes() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(verdict(&sb, "s1"), "ask");
    let out = output(&mut sb.command(), Some("o\n"));
    let shown = text(&out);
    assert!(shown.contains("openmoat allow --last"), "{shown}");
    assert!(!shown.contains("may run"), "{shown}");
    assert_eq!(verdict(&sb, "s1"), "ask");

    edit_policy(&sb);
    let before = lock(&sb);
    let out = output(&mut sb.command(), Some("y\n"));
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        text(&out).contains("openmoat doctor --accept"),
        "{}",
        text(&out)
    );
    assert_eq!(lock(&sb), before);
}

#[test]
fn file_ask_is_shown_and_allowed_once() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let notes = sb.home.join("notes.md");
    let payload = serde_json::json!({
        "session_id": "s1", "cwd": sb.project().to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": notes.to_string_lossy()}, "tool_use_id": "t1"
    })
    .to_string();
    let read = || hook_output(&sb.guard("claude-code", &payload))["permissionDecision"].clone();
    assert_eq!(read(), "ask");
    let shown = home_as_person(&sb, "o\n");
    assert!(
        shown.contains("today: 1 decision, 0 denied, 1 asked"),
        "{shown}"
    );
    assert!(shown.contains("Claude Code asked to read"), "{shown}");
    assert!(
        shown.contains("session s1 on claude-code may read"),
        "{shown}"
    );
    assert_eq!(read(), "allow");
}
