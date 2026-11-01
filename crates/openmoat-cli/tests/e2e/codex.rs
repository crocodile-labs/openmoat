//! Codex: its `PreToolUse` cannot ask, so an `ask` must still stop the call.

use crate::common::{DENY, OK, Sandbox, fixture, hook_output, stderr, stdout};

#[test]
fn bare_openmoat_denies_hook_input_but_keeps_the_home_screen() {
    let sb = Sandbox::installed(&[".codex"]);
    let out = sb.moat_stdin(&[], &shell("miswired", "cat ~/.ssh/id_rsa"));
    assert_eq!(out.status.code(), Some(DENY));
    assert!(stderr(&out).contains("without `guard --host <agent>`; denying"));
    for input in ["", "{}", "[]", "ordinary input"] {
        assert_eq!(sb.moat_stdin(&[], input).status.code(), Some(OK));
    }
}

#[test]
fn status_and_doctor_only_warn_about_codex_trust_without_granting_it() {
    let sb = Sandbox::installed(&[".codex"]);
    let config = sb.home.join(".codex/config.toml");
    let before = std::fs::read(&config).unwrap();
    for command in ["status", "doctor"] {
        let out = sb.moat(&[command]);
        assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
        assert!(stdout(&out).contains("installed but not trusted"));
        assert!(stdout(&out).contains("/hooks"));
    }
    assert_eq!(std::fs::read(&config).unwrap(), before);
    let out = sb.moat(&["status", "--format", "json"]);
    assert_eq!(out.status.code(), Some(OK));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        doc["hook_warnings"][0]
            .as_str()
            .unwrap()
            .contains("installed but not trusted")
    );
    sb.trust_codex_hook();
    for command in ["status", "doctor"] {
        let out = sb.moat(&[command]);
        assert_eq!(
            out.status.code(),
            Some(OK),
            "{} {}",
            stdout(&out),
            stderr(&out)
        );
        assert!(!stdout(&out).contains("installed but not trusted"));
    }
    let approved = std::fs::read_to_string(&config).unwrap();
    let key = format!(
        "{}:pre_tool_use:0:0",
        sb.home.join(".codex").join("hooks.json").display()
    );
    for (field, value) in [
        ("trusted_hash", toml_edit::value("sha256:old")),
        ("enabled", toml_edit::value(false)),
    ] {
        let mut doc: toml_edit::DocumentMut = approved.parse().unwrap();
        doc["hooks"]["state"][&key][field] = value;
        std::fs::write(&config, doc.to_string()).unwrap();
        let out = sb.moat(&["status"]);
        assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
        assert!(stdout(&out).contains("installed but not trusted"));
    }
    // The advisory mirror of Codex's internal hash is never an enforcement
    // input: valid guard calls and person-authorised commands still work.
    assert_eq!(
        sb.guard("codex", &shell("untrusted-allow", "ls -la"))
            .status
            .code(),
        Some(OK)
    );
    assert_eq!(
        sb.moat_as_person(&["sandbox", "sync"]).status.code(),
        Some(OK)
    );
}

#[cfg(windows)]
#[test]
fn codex_windows_command_forwards_stdin_and_preserves_guard_exit_codes() {
    use std::os::windows::process::CommandExt as _;

    let sb = Sandbox::installed(&[".codex"]);
    let path = sb.home.join(".codex/hooks.json");
    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let command = root["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"]
        .as_str()
        .unwrap();
    let run = |command: &str, payload: &str| {
        let mut cmd = sb.command_at(std::path::Path::new("cmd.exe"));
        // Exactly Codex rust-v0.166.0 build_command: /C followed by the
        // whole command line wrapped in raw double quotes, not argv quoting.
        cmd.arg("/C").raw_arg(format!(r#""{command}""#));
        crate::common::output(&mut cmd, Some(payload))
    };
    for (session, action, code, verdict) in [
        ("windows-deny", "cat ~/.ssh/id_rsa", DENY, "deny"),
        // Codex's allow is no output, which `hook_output` reads as `defer`.
        ("windows-allow", "ls -la", OK, "defer"),
    ] {
        let out = run(command, &shell(session, action));
        assert_eq!(
            out.status.code(),
            Some(code),
            "{} {}",
            stdout(&out),
            stderr(&out)
        );
        assert_eq!(hook_output(&out)["permissionDecision"], verdict);
    }
    let spec = openmoat_hosts::Host::Codex.spec().install.as_ref().unwrap();
    let missing = sb.home.join("Missing Moat's %PATH% tools/openmoat.exe");
    let entry = spec.hook_file.entries().unwrap().entry(
        &spec.hooks[0],
        "codex",
        &missing.to_string_lossy(),
        false,
    );
    let out = run(
        entry["hooks"][0]["commandWindows"].as_str().unwrap(),
        &shell("windows-missing", "ls -la"),
    );
    assert_eq!(
        out.status.code(),
        Some(DENY),
        "{} {}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        !stderr(&out).trim().is_empty(),
        "Codex requires a stderr reason to block"
    );
}

#[test]
fn codex_166_ssh_key_attack_is_denied_and_audited() {
    let sb = Sandbox::installed(&[".codex"]);
    let out = sb.guard("codex", &shell("codex-166-attack", "cat ~/.ssh/id_rsa"));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    assert_eq!(hook_output(&out)["permissionDecision"], "deny");
    let audit = sb.moat(&["audit", "export"]);
    assert!(stdout(&audit).contains("codex-166-attack"));
}

#[test]
fn installed_codex_command_executes_guard_from_a_path_with_shell_characters() {
    let sb = Sandbox::bare(&[".codex"]);
    let installed = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    // Quotes are valid POSIX filename characters; Windows permits apostrophes
    // and percent signs but not double quotes.
    let name = if cfg!(windows) {
        "Moat's %PATH% tools"
    } else {
        "Moat's \"$` tools"
    };
    let dir = installed.path().join(name);
    std::fs::create_dir(&dir).unwrap();
    let binary = dir.join(if cfg!(windows) {
        "openmoat.exe"
    } else {
        "openmoat"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_openmoat"), &binary).unwrap();
    let init = crate::common::output(sb.command_at(&binary).args(["init", "--yes"]), Some(""));
    assert_eq!(init.status.code(), Some(OK), "{}", stderr(&init));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".codex/hooks.json")).unwrap())
            .unwrap();
    let field = if cfg!(windows) {
        "commandWindows"
    } else {
        "command"
    };
    let command = doc["hooks"]["PreToolUse"][0]["hooks"][0][field]
        .as_str()
        .unwrap();
    let program = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
    let mut cmd = sb.command_at(std::path::Path::new(program));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.arg("/C").raw_arg(format!(r#""{command}""#));
    }
    #[cfg(not(windows))]
    cmd.args(["-lc", command]);
    let out = crate::common::output(
        &mut cmd,
        Some(&shell("shell-executed", "cat ~/.ssh/id_rsa")),
    );
    assert_eq!(
        out.status.code(),
        Some(DENY),
        "{} {}",
        stdout(&out),
        stderr(&out)
    );
    assert_eq!(hook_output(&out)["permissionDecision"], "deny");
    assert!(stdout(&sb.moat(&["audit", "export"])).contains("shell-executed"));
}

#[test]
fn legacy_codex_hook_is_reported_and_migrated_by_each_upgrade_path() {
    for args in [
        vec!["init", "--yes"],
        vec!["policy", "upgrade", "--yes"],
        vec!["sandbox", "sync"],
    ] {
        let sb = Sandbox::installed(&[".codex"]);
        let path = sb.home.join(".codex/hooks.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let hook = &mut doc["hooks"]["PreToolUse"][0]["hooks"][0];
        *hook = serde_json::json!({"type":"command", "command":env!("CARGO_BIN_EXE_openmoat"), "args":["guard","--host","codex"], "timeout":600});
        std::fs::write(&path, doc.to_string()).unwrap();
        // Model an intact lock written by the old release, rather than drift.
        let accepted = sb.moat_as_person(&["doctor", "--accept"]);
        assert!(
            stdout(&accepted).contains("re-pinned"),
            "{}",
            stdout(&accepted)
        );
        for command in ["status", "doctor"] {
            let out = sb.moat(&[command]);
            assert!(stdout(&out).contains("openmoat init"), "{}", stdout(&out));
            assert!(!out.status.success());
        }
        let out = sb.moat_as_person(&args);
        assert_eq!(
            out.status.code(),
            Some(OK),
            "{} {}",
            stdout(&out),
            stderr(&out)
        );
        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let hook = &updated["hooks"]["PreToolUse"][0]["hooks"][0];
        assert!(hook.get("args").is_none());
        assert!(
            hook["command"]
                .as_str()
                .unwrap()
                .ends_with(" guard --host codex")
        );
        assert_eq!(hook["statusMessage"], "OpenMoat");
        assert!(path.with_extension("json.moat-backup").exists());
        let denied = sb.guard("codex", &shell("migrated", "cat ~/.ssh/id_rsa"));
        assert_eq!(denied.status.code(), Some(DENY));
        assert!(!stderr(&denied).contains("kernel-integrity"));
        for command in ["status", "doctor"] {
            let out = sb.moat(&[command]);
            assert!(
                stdout(&out).contains("installed but not trusted"),
                "{}",
                stdout(&out)
            );
        }
    }
}

fn shell(session: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session,
        "turn_id": "t-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "call-1",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// Codex rejects `permissionDecision: "ask"` as unsupported and then runs the
/// call. An `ask` must therefore reach Codex as a blocking `deny` (exit 2) that
/// tells the person how to approve it, while the audit log keeps the `ask` so
/// `moat allow --last` can turn it into a session grant.
#[test]
fn an_ask_blocks_codex_until_a_person_approves_it() {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".codex")).unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(OK));

    // still an `ask` under ADR-025: a pager is a program git runs later
    let command = "git config core.pager less";
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    let d = hook_output(&out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("[git-internals]"), "{reason}");
    assert!(reason.contains("openmoat allow --last"), "{reason}");

    let allow = sb.moat_approving(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(OK), "{}", stderr(&allow));
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(OK), "approved for the session");
    // Codex's allow is no output (it rejects a bare `permissionDecision: allow`).
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));

    // Claude Code can ask, so it still receives the `ask` itself.
    let claude = serde_json::json!({
        "session_id": "s-claude", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": command }, "tool_use_id": "t1"
    });
    let out = sb.guard("claude-code", &claude.to_string());
    assert_eq!(out.status.code(), Some(OK));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");

    // A call no rule matches is left to Codex's own approval policy (ADR-025):
    // no output, exit 0, and never the blocking deny an `ask` becomes.
    let out = sb.guard("codex", &shell("codex-s2", "npm install left-pad"));
    assert_eq!(out.status.code(), Some(OK), "{}", stderr(&out));
    assert!(stdout(&out).trim().is_empty(), "{}", stdout(&out));
}

/// Codex runs `PermissionRequest` hooks only once it has decided to prompt, so
/// that event cannot carry an `ask` from `PreToolUse` (#178) and `moat init` does
/// not install it. If a person wires `guard` to it anyway, `guard` refuses the
/// event, even for a command it would allow: exit 2 with a reason on stderr,
/// which Codex reads as a deny, never as an approval.
#[test]
fn a_codex_permission_request_is_refused_never_approved() {
    let sb = Sandbox::installed(&[".codex"]);
    let out = sb.guard("codex", &fixture("codex/permission-request-shell.json"));
    assert_eq!(out.status.code(), Some(DENY), "{}", stderr(&out));
    assert!(stderr(&out).contains("moat: deny"), "{}", stderr(&out));
}
