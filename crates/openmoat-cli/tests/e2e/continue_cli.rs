//! The Continue CLI (`cn`) runs the Claude Code hook and ignores an `ask`, so an
//! `ask` must still stop a `cn` call.

use std::path::Path;
use std::process::Output;

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, bash_payload, fixture, hook_output, output, stderr, text};

/// Run the Claude Code hook as `cn` does: with `CONTINUE_PROJECT_DIR` set.
fn guard_under_cn(sb: &Sandbox, payload: &str) -> Output {
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", "claude-code"])
        .env("CONTINUE_PROJECT_DIR", &sb.home);
    output(&mut cmd, Some(payload))
}

fn recorded(sb: &Sandbox, session: &str) -> Value {
    let shown = sb.moat(&["show", "--session", session, "--format", "json"]);
    assert_eq!(shown.status.code(), Some(OK), "{}", stderr(&shown));
    serde_json::from_slice(&shown.stdout).unwrap()
}

fn assert_blocked_ask(out: &Output) {
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(out));
    let d = hook_output(out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("[git-internals]"), "{reason}");
    assert!(reason.contains("Continue CLI"), "{reason}");
    assert!(reason.contains("moat allow --last"), "{reason}");
}

/// `cn` runs the call when its hook answers `ask`. An `ask` must reach it as a
/// blocking `deny` (exit 2) that says how to approve it; the audit log records
/// the host as `continue` and keeps the `ask`, so `moat allow --last` grants it.
#[test]
fn an_ask_blocks_cn_until_a_person_approves_it() {
    let sb = Sandbox::installed(&[".claude"]);
    let cn = fixture("continue/pretooluse-bash.json");
    let session = "3f2a9c1e-7b4d-4e8a-9f0b-2c6d8e1a5b7f";

    assert_blocked_ask(&guard_under_cn(&sb, &cn));
    let events = recorded(&sb, session);
    assert_eq!(events[0]["host"], "continue", "{events}");
    assert_eq!(events[0]["verdict"], "ask", "{events}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = guard_under_cn(&sb, &cn);
    assert_eq!(out.status.code(), Some(OK), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // Claude Code can ask, so it still receives the `ask` itself.
    let claude = bash_payload("s-claude", &sb.home, "git config core.pager less");
    let out = sb.guard("claude-code", &claude);
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");
    assert_eq!(recorded(&sb, "s-claude")[0]["host"], "claude-code");
}

/// `moat doctor` and `moat status` with `PATH` set to `bin` and the extra
/// environment `env`.
fn checks(sb: &Sandbox, bin: &Path, env: &[(&str, &Path)]) -> [Output; 2] {
    ["doctor", "status"].map(|command| {
        let mut cmd = sb.command();
        cmd.arg(command).env("PATH", bin);
        for (key, value) in env {
            cmd.env(key, value);
        }
        output(&mut cmd, None)
    })
}

/// Released `cn` loads hooks but fires none, so its calls never reach
/// `guard`. `doctor` and `status` warn when it is present, without changing
/// their exit code, and say nothing when it is not.
#[test]
fn doctor_and_status_warn_when_the_continue_cli_is_present() {
    let sb = Sandbox::installed(&[".claude"]);
    let bin = sb.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let warning = "the released Continue CLI does not run hooks";

    let before = checks(&sb, &bin, &[]);
    for out in &before {
        assert!(!text(out).contains("Continue CLI"), "{}", text(out));
    }

    std::fs::create_dir_all(sb.home.join(".continue")).unwrap();
    for (out, earlier) in checks(&sb, &bin, &[]).iter().zip(&before) {
        assert!(text(out).contains(warning), "{}", text(out));
        assert!(text(out).contains("moat run"), "{}", text(out));
        assert_eq!(out.status.code(), earlier.status.code(), "{}", text(out));
    }

    // `cn` reads `CONTINUE_GLOBAL_DIR` instead of `~/.continue` when set.
    let elsewhere = sb.home.join("cn-global");
    let missing = [("CONTINUE_GLOBAL_DIR", elsewhere.as_path())];
    for out in checks(&sb, &bin, &missing) {
        assert!(!text(&out).contains(warning), "{}", text(&out));
    }
    std::fs::create_dir_all(&elsewhere).unwrap();
    for out in checks(&sb, &bin, &missing) {
        assert!(text(&out).contains(warning), "{}", text(&out));
        assert!(text(&out).contains("cn-global"), "{}", text(&out));
    }
}

/// `cn` on the search path is enough, with no Continue directory.
#[cfg(unix)]
#[test]
fn doctor_and_status_warn_when_cn_is_on_the_path() {
    use std::os::unix::fs::PermissionsExt as _;

    let sb = Sandbox::installed(&[".claude"]);
    let bin = sb.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let cn = bin.join("cn");
    std::fs::write(&cn, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&cn, std::fs::Permissions::from_mode(0o755)).unwrap();
    for out in checks(&sb, &bin, &[]) {
        assert!(
            text(&out).contains("the released Continue CLI does not run hooks"),
            "{}",
            text(&out)
        );
    }
}

/// Either sign of `cn` is enough on its own: its empty `transcript_path`
/// without the variable, or the variable with a Claude Code-shaped payload.
#[test]
fn either_sign_of_cn_turns_an_ask_into_a_deny() {
    let sb = Sandbox::installed(&[".claude"]);
    assert_blocked_ask(&sb.guard("claude-code", &fixture("continue/pretooluse-bash.json")));

    let claude_shaped = bash_payload("s-env", &sb.home, "git config core.pager less");
    assert_blocked_ask(&guard_under_cn(&sb, &claude_shaped));
    assert_eq!(recorded(&sb, "s-env")[0]["host"], "continue");
}
