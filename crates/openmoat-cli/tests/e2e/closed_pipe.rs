//! A reader that closes its end of the pipe early (`moat status | head -1`).
//!
//! Every command but `guard` stops quietly with exit 0, like other command-line
//! tools; a command that changes state finishes its work first. `guard` is a
//! hook, so an unwritable response is a deny (ADR-015), never exit 0.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use crate::common::{DENY, OK, Sandbox, bash_payload, stderr, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

/// Run `cmd` with its standard output already closed by the reader.
fn closed_stdout(cmd: &mut Command, stdin: &str) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning moat");
    drop(child.stdout.take());
    let mut pipe = child.stdin.take().expect("stdin is piped");
    // `guard` reads its payload; the others exit without reading stdin.
    let _ = pipe.write_all(stdin.as_bytes());
    drop(pipe);
    child.wait_with_output().unwrap()
}

fn assert_quiet_success(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(OK), "{what}: {}", text(out));
    assert!(!stderr(out).contains("panicked"), "{what}: {}", text(out));
}

#[test]
fn read_only_commands_stop_quietly() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    for args in [
        &["status"][..],
        &["policy", "lint"],
        &["doctor"],
        &["show"],
        &["policy", "check", "ls"],
    ] {
        let out = closed_stdout(sb.command().args(args), "");
        assert_quiet_success(&out, &args.join(" "));
        assert!(
            stderr(&out).is_empty(),
            "{}: {}",
            args.join(" "),
            text(&out)
        );
    }
}

#[test]
fn init_finishes_its_work_before_stopping() {
    let sb = Sandbox::bare(&[&dir_of(Host::ClaudeCode)]);
    let out = closed_stdout(sb.command().args(["init", "--yes"]), "");
    assert_quiet_success(&out, "init");
    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(OK), "{}", text(&status));
}

#[test]
fn allow_finishes_its_work_before_stopping() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let command = "npm install left-pad";
    let out = closed_stdout(
        sb.command()
            .args(["allow", command, "--always"])
            .env("MOAT_ASSUME_TTY", "1"),
        "",
    );
    assert_quiet_success(&out, "allow");
    // The overlay was written and the lock re-pinned: the kernel is healthy.
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
}

#[test]
fn guard_denies_when_it_cannot_answer() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let payload = bash_payload("s1", &sb.project(), "ls");
    let out = closed_stdout(
        sb.command()
            .args(["guard", "--host", Host::ClaudeCode.id()]),
        &payload,
    );
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
}
