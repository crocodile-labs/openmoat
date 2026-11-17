//! Other agents running Claude Code's hook (ADR-097), and the variable
//! `init` sets so a file the person `@`-mentions is read through the hook.

use crate::common::{Sandbox, fixture, stderr, stdout};
use openmoat_hosts::Host;

/// Grok Build and the Devin CLI run Claude Code's hook with their own tool
/// names: a secret read through one is denied with exit 2, which both read as
/// a block, never left ungoverned; a harmless call is no deny.
#[test]
fn another_agents_call_through_claude_codes_hook_is_checked() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    for name in ["grok-shell", "devin-exec"] {
        let out = sb.guard(
            Host::ClaudeCode.id(),
            &fixture(&format!("claude-code/{name}.json")),
        );
        assert_eq!(out.status.code(), Some(2), "{name}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("secrets-paths"),
            "{name}: {}",
            stderr(&out)
        );
    }
    let out = sb.guard(
        Host::ClaudeCode.id(),
        &fixture("claude-code/devin-read.json"),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let shown = sb.moat(&["show", "--recent", "3"]);
    assert!(
        !stdout(&shown).contains("(ungoverned)"),
        "{}",
        stdout(&shown)
    );
}

/// `init` writes `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` into the user
/// settings' `env`, and `status` counts the hook installed with it
/// (`uninstall`: `install/hook_file/tests/claude.rs`).
#[test]
fn init_sends_file_mentions_through_the_hook() {
    let sb = Sandbox::bare(&[".claude"]);
    sb.moat(&["init", "--yes"]);
    let path = sb.home.join(".claude/settings.json");
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(settings["env"]["CLAUDE_CODE_DISABLE_FILE_MENTIONS"], "1");
    let status = sb.moat(&["status"]);
    assert!(
        !stdout(&status).contains("run `openmoat init`"),
        "{}",
        stdout(&status)
    );
}
