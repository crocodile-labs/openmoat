//! The guard checks its own binary against the digest the lock recorded
//! (ADR-071): other bytes under the same release deny every call, an upgrade
//! in place is only reported, and `openmoat init` records the binary again.

use serde_json::Value;

use super::{guard_read_src, lock_path, sandbox};
use crate::common::{DENY, OK, Sandbox, text};

fn lock(sb: &Sandbox) -> Value {
    serde_json::from_str(&std::fs::read_to_string(lock_path(sb)).unwrap()).unwrap()
}

/// The lock with `key` set to `value`, as a file changed under it would read.
fn set(sb: &Sandbox, key: &str, value: &str) {
    let mut doc = lock(sb);
    doc[key] = Value::from(value);
    std::fs::write(lock_path(sb), doc.to_string()).unwrap();
}

#[test]
fn a_binary_changed_under_its_release_denies_until_init() {
    let sb = sandbox();
    let recorded = lock(&sb);
    let digest = recorded["binary_sha256"].as_str().unwrap().to_owned();
    assert_eq!(digest.len(), 64, "{recorded}");
    assert_eq!(recorded["binary_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(guard_read_src(&sb)["exit"], OK);

    set(&sb, "binary_sha256", &"0".repeat(64));
    let denied = guard_read_src(&sb);
    assert_eq!(denied["exit"], DENY, "{denied}");
    assert_eq!(denied["permissionDecision"], "deny", "{denied}");
    let reason = denied["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    for command in ["status", "doctor"] {
        let out = sb.moat(&[command]);
        assert!(
            text(&out).contains("changed since the lock recorded it"),
            "{command}: {}",
            text(&out)
        );
        assert!(!out.status.success(), "{command}");
    }

    let init = sb.moat(&["init", "--yes"]);
    assert_eq!(init.status.code(), Some(OK), "{}", text(&init));
    assert_eq!(lock(&sb)["binary_sha256"], Value::from(digest));
    assert_eq!(guard_read_src(&sb)["exit"], OK);
}

#[test]
fn an_upgrade_in_place_is_reported_not_denied() {
    let sb = sandbox();
    set(&sb, "binary_version", "0.0.1");
    set(&sb, "binary_sha256", &"0".repeat(64));
    assert_eq!(guard_read_src(&sb)["exit"], OK);
    let out = sb.moat(&["status"]);
    assert!(
        text(&out).contains("the lock recorded 0.0.1"),
        "{}",
        text(&out)
    );
}
