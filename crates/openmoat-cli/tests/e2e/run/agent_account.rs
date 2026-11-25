//! `openmoat agent-account` (ADR-129) where it cannot change anything:
//! every other system refuses each command with exit 64, and on Windows
//! setup refuses without a person at a terminal or without an administrator
//! token, saying how to run it.

use crate::common::{Sandbox, USAGE, stderr, text};

/// Windows, elevated: setup, a run as the agent account, remove.
#[cfg(windows)]
mod windows;

/// Off Windows, setup, status and remove each say `openmoat run` needs no
/// account here, and exit 64.
#[cfg(not(windows))]
#[test]
fn every_command_refuses_off_windows() {
    let sb = Sandbox::installed(&[]);
    for command in ["setup", "status", "remove"] {
        let out = sb.moat_as_person(&["agent-account", command]);
        assert_eq!(out.status.code(), Some(USAGE), "{command}: {}", text(&out));
        assert!(
            stderr(&out).contains("needs no account"),
            "{command}: {}",
            text(&out)
        );
    }
}

/// On Windows, setup from a script is refused before anything else, and
/// from a person's terminal without an administrator token it says to use
/// one. CI's runner is elevated, so the second case is forced with a switch
/// only debug builds read, which can only make setup refuse; an unelevated
/// token of the runner's own is not tested.
#[cfg(windows)]
#[test]
fn setup_refuses_a_script_and_an_unelevated_terminal() {
    use crate::common::output;

    let sb = Sandbox::installed(&[]);
    let out = sb.moat(&["agent-account", "setup"]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("by a person"), "{}", text(&out));

    let out = output(
        sb.command()
            .args(["agent-account", "setup"])
            .env("MOAT_ASSUME_TTY", "1")
            .env("MOAT_TEST_NOT_ELEVATED", "1"),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        stderr(&out).contains("administrator terminal"),
        "{}",
        text(&out)
    );
    assert!(!sb.home.join(".moat/agent-account.json").exists());

    // Nothing set up: status says so and exits 0.
    let out = sb.moat(&["agent-account", "status"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("no agent account"), "{}", text(&out));
}
