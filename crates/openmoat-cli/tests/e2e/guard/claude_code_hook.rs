//! What `init` writes beside Claude Code's hook entries.

use crate::common::{Sandbox, stdout};

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
