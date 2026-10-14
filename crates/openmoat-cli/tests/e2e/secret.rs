//! `moat secret add`, end to end: the policy entry, the diff and question, the
//! re-pin and the synced sandbox settings.

use std::fs;
use std::process::Output;

use crate::common::{OK, Sandbox, USAGE, output, text};

fn add(sb: &Sandbox, args: &[&str], answer: &str) -> Output {
    let mut cmd = sb.command();
    cmd.args(["secret", "add"])
        .args(args)
        .env("MOAT_ASSUME_TTY", "1");
    output(&mut cmd, Some(answer))
}

fn policy(sb: &Sandbox) -> String {
    fs::read_to_string(sb.home.join(".moat/policy.yaml")).unwrap()
}

#[test]
fn secret_add_without_a_terminal_is_refused() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["secret", "add", "gh"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("must be run by a person in a terminal"));
}

#[test]
fn secret_add_gh_shows_the_change_and_applies_only_on_yes() {
    let sb = Sandbox::installed(&[".claude"]);
    let before = policy(&sb);

    let out = add(&sb, &["gh"], "n\n");
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("+  - id: gh")
            && message.contains("+    host: api.github.com")
            && message.contains("moat-secret:gh:placeholder")
            && message.contains("Apply? [y/N]"),
        "{message}"
    );
    assert_eq!(policy(&sb), before, "nothing written on no");

    let out = add(&sb, &["gh"], "y\n");
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("lock re-pinned") && message.contains("new agent session"),
        "{message}"
    );
    assert!(policy(&sb).contains("env: GITHUB_TOKEN"));
    if cfg!(not(windows)) {
        // #327: no Claude Code sandbox on native Windows
        let settings = fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap();
        assert!(settings.contains("GITHUB_TOKEN"), "{settings}");
    }
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));

    let again = add(&sb, &["gh"], "y\n");
    assert_ne!(again.status.code(), Some(OK));
    assert!(text(&again).contains("already brokers a secret `gh`"));
}

#[test]
fn secret_add_needs_a_host_for_any_other_id() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = add(&sb, &["api", "--env", "API_KEY"], "y\n");
    assert_ne!(out.status.code(), Some(OK));
    assert!(text(&out).contains("give --host"), "{}", text(&out));
}
