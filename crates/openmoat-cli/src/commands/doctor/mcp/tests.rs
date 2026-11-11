use serde_json::json;

use super::*;
use crate::install::Recorded;
use crate::integrity::{self, HookPins};
use crate::mcp::pins::{Pins, ServerPin};
use crate::render::Deferred;

/// A lock an older version wrote, keeping an OpenCode `environment` value in
/// clear, written as it was (a save would hide the value).
fn old_lock(home: &Home, binary: &Path) {
    let mut lock = integrity::repin(home, binary, HookPins::Adopt).unwrap();
    let pin = ServerPin {
        host: "opencode".to_owned(),
        name: "db".to_owned(),
        file: "/c/opencode.json".to_owned(),
        digest: "00".to_owned(),
        shown: json!({"type": "local", "command": ["db"],
            "environment": {"API_KEY": "kept-secret-value"}}),
    };
    lock.mcp_servers = Some(Pins::from([("/c/opencode.json#/mcp/db".to_owned(), pin)]));
    std::fs::write(
        home.lock_path(),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
}

/// After drift, `--accept` re-pins first, and that save already hides the
/// value: the row is decided from the lock now on disk, so it goes, and the
/// command does not fail over what it has just fixed.
#[test]
fn the_clear_values_row_goes_once_the_lock_holds_none_whoever_removed_them() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    Recorded::default().save(&home).unwrap();
    std::fs::write(home.policy_path(), "version: 1\n").unwrap();
    let binary = Path::new("/x/openmoat");
    old_lock(&home, binary);
    let lock = Lock::load(&home.lock_path()).unwrap();
    let mut report = Report::new(Deferred::quiet());
    lines(&mut report, &home, &lock, binary);
    assert!(
        report
            .problems
            .iter()
            .any(|(_, line)| line.starts_with(CLEAR_VALUES)),
        "{:?}",
        report.problems
    );

    // What `doctor --accept` does over drift: re-pin, then accept MCP.
    integrity::repin(&home, binary, HookPins::Keep).unwrap();
    accept(&mut report, &home, binary).unwrap();
    assert!(
        !report
            .problems
            .iter()
            .any(|(_, line)| line.starts_with(CLEAR_VALUES)),
        "{:?}",
        report.problems
    );
    let text = std::fs::read_to_string(home.lock_path()).unwrap();
    assert!(!text.contains("kept-secret-value"), "{text}");
}
