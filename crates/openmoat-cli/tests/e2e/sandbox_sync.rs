//! Standard tier (ADR-018): `init` and `sandbox sync` write the host sandboxes,
//! the lock pins them, and `doctor` names every weakened setting.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, USAGE, fixture, stdout, text};

fn claude_settings(sb: &Sandbox) -> PathBuf {
    sb.home.join(".claude/settings.json")
}

fn codex_config(sb: &Sandbox) -> PathBuf {
    sb.home.join(".codex/config.toml")
}

/// Both hosts present, each with a setting of the user's own, then `init`.
fn installed() -> Sandbox {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    fs::write(
        claude_settings(&sb),
        r#"{"theme":"dark","permissions":{"allow":["Bash(ls)"]}}"#,
    )
    .unwrap();
    fs::write(codex_config(&sb), "# my settings\nmodel = \"o3\"\n").unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    sb
}

fn settings(sb: &Sandbox) -> Value {
    serde_json::from_str(&fs::read_to_string(claude_settings(sb)).unwrap()).unwrap()
}

fn codex_shell(command: &str) -> String {
    serde_json::json!({
        "session_id": "s", "turn_id": "t", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_use_id": "c", "tool_input": { "command": command },
    })
    .to_string()
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn init_writes_both_sandboxes_keeps_user_settings_and_pins_them() {
    let sb = installed();
    let claude = settings(&sb);
    assert_eq!(claude["sandbox"]["enabled"], Value::Bool(true));
    assert_eq!(claude["sandbox"]["failIfUnavailable"], Value::Bool(true));
    assert_eq!(
        claude["sandbox"]["allowUnsandboxedCommands"],
        Value::Bool(false)
    );
    assert_eq!(
        claude["permissions"]["blockReadsOutsideWorkingDirectories"],
        Value::Bool(true)
    );
    assert_eq!(claude["theme"], "dark");
    assert_eq!(claude["permissions"]["allow"][0], "Bash(ls)");
    assert!(
        claude["hooks"]["PreToolUse"].is_array(),
        "hooks still installed"
    );

    let codex = fs::read_to_string(codex_config(&sb)).unwrap();
    for expected in [
        "# my settings",
        "model = \"o3\"",
        "default_permissions = \"moat\"",
        "[permissions.moat.filesystem]",
    ] {
        assert!(codex.contains(expected), "{expected}: {codex}");
    }
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    assert_eq!(
        lock["codex_profiles"].as_object().map(serde_json::Map::len),
        Some(1),
        "{lock}"
    );

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("Codex            sandbox matches the policy"),
        "{}",
        text(&doctor)
    );
    assert!(
        stdout(&doctor).contains("wider; --verbose for details)"),
        "{}",
        text(&doctor)
    );
    assert!(
        !stdout(&doctor).contains("stricter: "),
        "the list waits for --verbose"
    );
    let verbose = sb.moat(&["doctor", "--verbose"]);
    assert!(
        stdout(&verbose).contains("stricter: fs.write `codex.git`"),
        "losses are printed with --verbose"
    );
}

#[test]
fn sync_is_person_only_and_idempotent() {
    let sb = installed();
    let refused = sb.moat(&["sandbox", "sync"]);
    assert_eq!(refused.status.code(), Some(USAGE), "{}", text(&refused));
    assert!(text(&refused).contains("must be run by a person"));

    let before = (
        fs::read(claude_settings(&sb)).unwrap(),
        fs::read(codex_config(&sb)).unwrap(),
    );
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stdout(&out).contains("(sandbox unchanged)"),
        "{}",
        stdout(&out)
    );
    let after = (
        fs::read(claude_settings(&sb)).unwrap(),
        fs::read(codex_config(&sb)).unwrap(),
    );
    assert_eq!(before, after, "sync after init changes nothing");
    assert_eq!(sb.moat(&["status"]).status.code(), Some(OK));
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn a_tampered_sandbox_block_denies_every_call_and_sync_refuses_over_it() {
    let sb = installed();
    let mut claude = settings(&sb);
    claude["sandbox"]["excludedCommands"] = serde_json::json!(["curl"]);
    fs::write(claude_settings(&sb), claude.to_string()).unwrap();

    let out = sb.guard("claude-code", &fixture("claude-code/read.json"));
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE));
    assert!(
        stdout(&doctor).contains("sandbox.excludedCommands is not empty"),
        "{}",
        stdout(&doctor)
    );

    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(USAGE), "{}", text(&sync));
    assert!(text(&sync).contains("drift"), "{}", text(&sync));
}

#[test]
fn codex_may_edit_its_own_keys_but_not_the_moat_profile() {
    let sb = installed();
    let path = codex_config(&sb);
    // What Codex writes itself when a project is trusted.
    let trusted =
        fs::read_to_string(&path).unwrap() + "\n[projects.\"/w\"]\ntrust_level = \"trusted\"\n";
    fs::write(&path, trusted).unwrap();
    let out = sb.guard("codex", &codex_shell("ls"));
    // Codex's allow is no output (it rejects a bare `permissionDecision: allow`).
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).is_empty(), "{}", text(&out));

    let weakened = fs::read_to_string(&path).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(&path, weakened).unwrap();
    let out = sb.guard("codex", &codex_shell("ls"));
    assert_eq!(out.status.code(), Some(DENY));
    assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));

    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        stdout(&accepted).contains("lock re-pinned"),
        "{}",
        text(&accepted)
    );
    assert!(
        stdout(&accepted).contains("default_permissions is not \"moat\""),
        "accepting the edit does not hide the weakness: {}",
        stdout(&accepted)
    );
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("default_permissions = \"moat\"")
    );
    assert_eq!(sb.moat(&["doctor"]).status.code(), Some(OK));
}

/// #327: Claude Code's sandbox cannot run on native Windows (with
/// `failIfUnavailable` Claude Code would not start), so `init` leaves it out and
/// every command says why instead of reporting it missing.
#[cfg(windows)]
#[test]
fn native_windows_leaves_out_the_claude_code_sandbox() {
    let note = "Claude Code      sandbox not available on native Windows; \
                the hook still applies the policy (use WSL2 for OS confinement)";
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let init = sb.moat(&["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert!(stdout(&init).contains(note), "{}", text(&init));
    let claude = settings(&sb);
    assert!(claude.get("sandbox").is_none(), "{claude}");
    let permissions = claude["permissions"].as_object().unwrap();
    assert_eq!(permissions.keys().collect::<Vec<_>>(), ["deny"], "{claude}");
    assert!(claude["hooks"]["PreToolUse"].is_array(), "{claude}");
    let read = sb.guard("claude-code", &fixture("claude-code/read.json"));
    assert_eq!(verdict(&read), "allow", "{}", text(&read));
    let codex = fs::read_to_string(codex_config(&sb)).unwrap();
    assert!(codex.contains("default_permissions = \"moat\""), "{codex}");

    let doctor = sb.moat(&["doctor"]);
    let status = sb.moat(&["status"]);
    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    for out in [doctor, status, sync] {
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        let shown = stdout(&out);
        assert!(
            shown.contains("sandbox not available on native Windows"),
            "{shown}"
        );
        assert!(!shown.contains("failIfUnavailable"), "{shown}");
        assert!(!shown.contains('\u{2717}'), "no problem reported: {shown}");
    }
    assert!(
        settings(&sb).get("sandbox").is_none(),
        "sync leaves it out too"
    );
}

/// #327: on native Windows `init` removes the sandbox settings an older version
/// wrote, which stopped Claude Code from starting, and keeps the user's own;
/// Claude Code's deny rules are written there all the same.
#[cfg(windows)]
#[test]
fn native_windows_init_removes_an_old_claude_code_sandbox() {
    let sb = Sandbox::bare(&[".claude"]);
    fs::write(
        claude_settings(&sb),
        r#"{"theme":"dark","permissions":{"allow":["Bash(ls)"],"blockReadsOutsideWorkingDirectories":true},
            "sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false}}"#,
    )
    .unwrap();
    let init = sb.moat(&["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert!(
        stdout(&init).contains("an older OpenMoat's are removed"),
        "{}",
        text(&init)
    );
    let claude = settings(&sb);
    assert!(claude.get("sandbox").is_none(), "{claude}");
    assert_eq!(
        claude["permissions"]["allow"],
        serde_json::json!(["Bash(ls)"])
    );
    assert!(
        claude["permissions"]
            .get("blockReadsOutsideWorkingDirectories")
            .is_none()
    );
    let deny = claude["permissions"]["deny"].as_array().unwrap();
    assert!(deny.contains(&"Edit(//**/bin/moat.exe)".into()), "{claude}");
    assert_eq!(claude["theme"], "dark");
    assert!(claude["hooks"]["PreToolUse"].is_array(), "{claude}");
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(
        doctor.status.code(),
        Some(OK),
        "re-pinned: {}",
        text(&doctor)
    );
}

/// The files in `dir` whose names end in OpenMoat's backup suffix.
fn sandbox_backups(dir: &std::path::Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("moat-sandbox-backup"))
        .collect()
}

/// An agent `init` left out keeps its files byte for byte: `sync` writes only
/// the agents that are set up and says how to add the others.
#[test]
fn sync_leaves_agents_init_left_out_untouched() {
    let sb = Sandbox::bare(&[".claude", ".codex", ".cursor"]);
    let mine = "# my settings\nmodel = \"o3\"\n";
    fs::write(codex_config(&sb), mine).unwrap();
    let init = sb.moat(&["init", "--hosts", "claude-code", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert_eq!(fs::read_to_string(codex_config(&sb)).unwrap(), mine);

    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    let shown = stdout(&sync);
    for line in [
        "· Codex            not set up (`openmoat init --hosts codex` adds it)",
        "· Cursor           not set up (`openmoat init --hosts cursor` adds it)",
        "Claude Code",
    ] {
        assert!(shown.contains(line), "{line}: {shown}");
    }
    assert_eq!(fs::read_to_string(codex_config(&sb)).unwrap(), mine);
    assert!(sandbox_backups(&sb.home.join(".codex")).is_empty());
    assert!(!sb.home.join(".cursor/sandbox.json").exists());
    let lock = fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap();
    assert!(!lock.contains(".codex"), "{lock}");
    assert!(!lock.contains(".cursor"), "{lock}");
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn sync_updates_every_agent_init_set_up() {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let init = sb.moat(&["init", "--hosts", "claude-code,codex", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    let mut claude = settings(&sb);
    claude["sandbox"]["enabled"] = Value::Bool(false);
    fs::write(claude_settings(&sb), claude.to_string()).unwrap();
    let weakened = fs::read_to_string(codex_config(&sb)).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(codex_config(&sb), weakened).unwrap();
    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        stdout(&accepted).contains("lock re-pinned"),
        "{}",
        text(&accepted)
    );

    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    let shown = stdout(&sync);
    assert_eq!(shown.matches("(sandbox updated)").count(), 2, "{shown}");
    assert_eq!(settings(&sb)["sandbox"]["enabled"], Value::Bool(true));
    let codex = fs::read_to_string(codex_config(&sb)).unwrap();
    assert!(codex.contains("default_permissions = \"moat\""), "{codex}");
}

/// Every file below the agents' directories, by path.
fn agent_files(sb: &Sandbox) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    [".claude", ".codex", ".cursor"]
        .iter()
        .flat_map(|dir| fs::read_dir(sb.home.join(dir)).unwrap())
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect()
}

/// After a full `moat uninstall` no agent is set up, so `sync` writes none of
/// them and pins none of their files, though their folders are all there.
#[test]
fn sync_after_a_full_uninstall_writes_no_agent() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let uninstall = sb.moat_as_person(&["uninstall"]);
    assert_eq!(uninstall.status.code(), Some(OK), "{}", text(&uninstall));
    let before = agent_files(&sb);

    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(OK), "{}", text(&sync));
    let shown = stdout(&sync);
    assert_eq!(
        shown.matches("not set up (`openmoat init --hosts").count(),
        3,
        "{shown}"
    );
    assert_eq!(agent_files(&sb), before);
    let lock = fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap();
    for dir in [".claude", ".codex", ".cursor"] {
        assert!(!lock.contains(dir), "{dir}: {lock}");
    }
}
