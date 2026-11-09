//! An agent's write that turns a host's hook off in a project's settings is
//! denied (`project-settings`), whatever tool makes it; any other change to
//! the same file keeps its review (`runs-later`). The unit tests in
//! `project_settings/written/tests.rs` cover each host's tools and spellings.

use std::fs;

use serde_json::json;

use crate::common::{Sandbox, verdict_and_reason};

fn write(sb: &Sandbox, file: &str, content: &str) -> (String, String) {
    let project = sb.project();
    let payload = json!({
        "session_id": "s1", "cwd": project.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "Write", "tool_use_id": "t1",
        "tool_input": {"file_path": project.join(file).to_string_lossy(), "content": content},
    });
    verdict_and_reason(&sb.guard("claude-code", &payload.to_string()))
}

#[test]
fn a_write_that_turns_a_hook_off_is_denied_and_other_edits_keep_their_review() {
    let sb = Sandbox::installed(&[".claude"]);
    fs::create_dir_all(sb.project().join(".codex")).unwrap();
    fs::create_dir_all(sb.project().join(".pi")).unwrap();

    for (file, content) in [
        (".codex/config.toml", "[features]\nhooks = false\n"),
        ("opencode.json", r#"{"plugin": ["-openmoat"]}"#),
        (".pi/settings.json", r#"{"extensions": ["!**"]}"#),
    ] {
        let (verdict, reason) = write(&sb, file, content);
        assert_eq!(verdict, "deny", "{file}: {reason}");
        assert!(reason.contains("project-settings"), "{file}: {reason}");
    }
    for (file, content) in [
        (
            ".codex/config.toml",
            "model = \"gpt-5\"\n[mcp_servers.db]\ncommand = \"db\"\n",
        ),
        (
            "opencode.json",
            r#"{"model": "x/y", "plugin": ["opencode-helper"]}"#,
        ),
        (".pi/settings.json", r#"{"packages": ["npm:x"]}"#),
    ] {
        let (verdict, reason) = write(&sb, file, content);
        assert_eq!(verdict, "ask", "{file}: {reason}");
        assert!(reason.contains("runs-later"), "{file}: {reason}");
    }
}

fn shell(sb: &Sandbox, command: &str) -> (String, String) {
    let payload = json!({
        "session_id": "s1", "cwd": sb.project().to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_use_id": "t1", "tool_input": {"command": command},
    });
    verdict_and_reason(&sb.guard("claude-code", &payload.to_string()))
}

/// What a shell write leaves cannot be known before it runs, so one aimed at a
/// hook settings file of a host OpenMoat is set up for is denied; other shell
/// work on the same project keeps its verdict.
#[test]
fn a_shell_write_of_hook_settings_is_denied_and_other_shell_work_is_not() {
    let sb = Sandbox::installed(&[".claude", ".codex"]);
    fs::create_dir_all(sb.project().join(".codex")).unwrap();
    for command in [
        "printf x > .codex/config.toml",
        "printf x >> .codex/config.toml",
        "printf x | tee .codex/config.toml",
        "cp evil.toml .codex/config.toml",
        "mv evil.toml .codex/config.toml",
    ] {
        let (verdict, reason) = shell(&sb, command);
        assert_eq!(verdict, "deny", "{command}: {reason}");
        assert!(reason.contains("project-settings"), "{command}: {reason}");
    }
    for command in [
        "cat .codex/config.toml",
        "git diff -- .codex/config.toml",
        "rm -f .codex/config.toml",
        "printf x > templates/config.toml",
    ] {
        let (verdict, reason) = shell(&sb, command);
        assert_ne!(verdict, "deny", "{command}: {reason}");
    }
}
