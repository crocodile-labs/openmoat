//! Windows phase 1 (ADR-083): work handed to WSL is denied by the hook on
//! every system; on Windows, the state directory's access list `init` sets and
//! `doctor` reads back, and Codex's Windows sandbox mode in `doctor`.

use crate::common::{Sandbox, bash_payload, stderr, verdict_and_reason};

/// The hook answers each crossing into WSL with a deny and exit 2, so the
/// host never runs it, and leaves a plain command alone.
#[test]
fn the_hook_denies_work_handed_to_wsl() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    for command in [
        "wsl cat ~/.ssh/id_rsa",
        "'C:\\Windows\\System32\\wsl.exe' -e cat /etc/shadow",
        "cmd /c \"WSL.EXE cat /home/me/.netrc\"",
        "cat '\\\\wsl$\\Ubuntu\\home\\me\\.ssh\\id_rsa'",
    ] {
        let out = sb.guard("claude-code", &bash_payload("s-wsl", &project, command));
        let (verdict, reason) = verdict_and_reason(&out);
        assert_eq!(verdict, "deny", "{command}: {}", stderr(&out));
        assert_eq!(out.status.code(), Some(2), "{command}");
        assert!(reason.contains("wsl-crossing"), "{command}: {reason}");
    }
    let read = serde_json::json!({
        "session_id": "s-wsl", "cwd": project.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": "//wsl.localhost/Ubuntu/home/me/.aws/credentials"},
        "tool_use_id": "t1"
    });
    let out = sb.guard("claude-code", &read.to_string());
    let (verdict, reason) = verdict_and_reason(&out);
    assert_eq!(verdict, "deny", "{}", stderr(&out));
    assert!(reason.contains("wsl-crossing"), "{reason}");
    let out = sb.guard(
        "claude-code",
        &bash_payload("s-wsl", &project, "git status"),
    );
    assert_ne!(verdict_and_reason(&out).0, "deny", "{}", stderr(&out));
}

/// `init` leaves only this account and `SYSTEM` on the state directory,
/// `doctor` names an account given a change right afterwards, and the next
/// `init` takes that entry out again.
#[cfg(windows)]
#[test]
fn the_state_directory_has_its_own_access_list() {
    use crate::common::stdout;

    let sb = Sandbox::installed(&[".claude"]);
    let shown = stdout(&sb.moat(&["doctor", "--format", "json"]));
    assert!(shown.contains("no other account may open it"), "{shown}");
    assert!(shown.contains("the agent runs as you"), "{shown}");

    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let icacls = std::path::Path::new(&root).join(r"System32\icacls.exe");
    let widened = std::process::Command::new(&icacls)
        .arg(sb.home.join(".moat"))
        .args(["/grant", "*S-1-1-0:(OI)(CI)M", "/q"])
        .status()
        .unwrap();
    assert!(widened.success());
    let shown = stdout(&sb.moat(&["doctor", "--format", "json"]));
    assert!(shown.contains("may be changed by Everyone"), "{shown}");
    assert!(shown.contains("/remove *S-1-1-0"), "{shown}");

    let again = sb.moat_as_person(&["init", "--yes"]);
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    let shown = stdout(&sb.moat(&["doctor", "--format", "json"]));
    assert!(shown.contains("no other account may open it"), "{shown}");
    assert!(!shown.contains("may be changed by"), "{shown}");
}

/// `doctor` reads Codex's `[windows] sandbox` and warns under `unelevated`.
#[cfg(windows)]
#[test]
fn doctor_shows_codexs_windows_sandbox_mode() {
    use crate::common::stdout;

    let sb = Sandbox::installed(&[".codex"]);
    let config = sb.home.join(".codex/config.toml");
    let written = std::fs::read_to_string(&config).unwrap_or_default();
    for (mode, said) in [
        ("elevated", "elevated sandbox enforces"),
        ("unelevated", "does not support denied read paths"),
    ] {
        let text = format!("{written}\n[windows]\nsandbox = \"{mode}\"\n");
        std::fs::write(&config, text).unwrap();
        let shown = stdout(&sb.moat(&["doctor", "--format", "json"]));
        assert!(shown.contains(said), "{mode}: {shown}");
    }
}
