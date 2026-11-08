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
