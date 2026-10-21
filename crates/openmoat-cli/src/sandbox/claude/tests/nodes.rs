//! Directory nodes and the state directory in the generated settings.

use super::*;

/// The working directory's `.cursor`, `.codex`, `.copilot` and `.gemini` are
/// directory nodes `denyWrite` leaves out; on every OS a literal rule for the
/// file below each makes Claude Code's sandbox keep the directory itself from
/// being moved on macOS, without making the rest of it read-only. `.claude` is
/// Claude Code's own.
#[test]
fn another_agents_directory_in_the_working_directory_gets_a_literal_rule() {
    let mac = generated(DEFAULT_POLICY);
    for expected in [
        "Edit(./.cursor/hooks.json)",
        "Edit(./.cursor/sandbox.json)",
        "Edit(./.codex/hooks.json)",
        "Edit(./.copilot/hooks)",
        "Edit(./.copilot/settings.json)",
        "Edit(./.copilot/config.json)",
        "Edit(./.gemini/settings.json)",
    ] {
        assert!(
            mac.deny_rules.contains(&expected.to_owned()),
            "{expected}: {:?}",
            mac.deny_rules
        );
    }
    assert!(
        !mac.deny_rules
            .iter()
            .any(|r| r.starts_with("Edit(./.claude"))
    );
    assert!(!mac.deny_rules.iter().any(|r| r.starts_with("Read(./")));
    let deny = list(&mac, "/filesystem/denyWrite");
    for node in ["/**/.cursor", "/**/.codex", "/**/.copilot", "/**/.gemini"] {
        assert!(
            !deny.contains(&node.to_owned()),
            "{node} stays writable inside"
        );
    }
}

/// On Linux the audit log's `-wal` and `-shm` files, made after a command
/// starts, are not matched by the `audit.db*` glob the runtime expanded at
/// that start: the whole state directory is hidden, and only on Linux.
#[test]
fn on_linux_the_state_directory_is_hidden_whole() {
    let linux = generated_for(DEFAULT_POLICY, true);
    let deny = list(&linux, "/filesystem/denyRead");
    assert!(deny.contains(&"/Users/me/.moat".to_owned()), "{deny:?}");
    assert!(deny.contains(&"/Users/me/.moat/audit.db*".to_owned()));
    assert!(
        !deny.iter().any(|d| d == "/**/.moat"),
        "a glob directory is not hidden: the project's `.moat` holds its policy"
    );
    let loss = linux
        .report
        .losses
        .iter()
        .find(|l| l.rule == "claude-code.linux-state-dir");
    assert!(
        loss.is_some_and(|l| l.message.contains("-wal")),
        "{:?}",
        linux.report
    );
    assert!(
        !linux
            .deny_rules
            .contains(&"Read(//Users/me/.moat)".to_owned()),
        "Claude Code's file tools still read the policy"
    );
    let mac = generated(DEFAULT_POLICY);
    assert!(!list(&mac, "/filesystem/denyRead").contains(&"/Users/me/.moat".to_owned()));
}
