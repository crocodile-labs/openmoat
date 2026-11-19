//! `openmoat policy migrate` (ADR-103): a policy rewritten in the current
//! policy schema without a rule changing, shown first, applied only by a
//! person at a terminal, the previous file kept, the lock re-pinned.

use crate::common::{OK, Sandbox, USAGE, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

/// A policy as someone wrote it by hand before 0.14.0: no `version:`, `ask`.
const BY_HAND: &str = "# ours\ndefaults: { \"*\": ask, net: deny }\nask:\n  - id: deploy\n    \
                       shell: [\"make deploy\"]\n";

fn installed() -> Sandbox {
    Sandbox::installed(&[&dir_of(Host::ClaudeCode)])
}

#[test]
fn a_current_policy_has_nothing_to_migrate() {
    let sb = installed();
    for args in [
        &["policy", "migrate", "--dry-run"][..],
        &["policy", "migrate"],
    ] {
        let out = sb.moat(args);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(text(&out).contains("nothing to migrate"), "{}", text(&out));
    }
}

#[test]
fn a_file_is_shown_then_migrated_by_a_person_with_the_old_one_kept() {
    let sb = installed();
    let file = sb.project().join("policy.yaml");
    std::fs::write(&file, BY_HAND).unwrap();
    let path = file.to_str().unwrap();

    let lint = sb.moat(&["policy", "lint", path]);
    assert_eq!(lint.status.code(), Some(USAGE), "{}", text(&lint));
    assert!(
        text(&lint).contains("openmoat policy migrate"),
        "{}",
        text(&lint)
    );

    let shown = sb.moat(&["policy", "migrate", "--file", path, "--dry-run"]);
    assert_eq!(shown.status.code(), Some(OK), "{}", text(&shown));
    assert!(text(&shown).contains("+version: 1"), "{}", text(&shown));
    assert!(text(&shown).contains("+review:"), "{}", text(&shown));
    assert!(
        text(&shown).contains("Nothing was changed"),
        "{}",
        text(&shown)
    );

    // No terminal: nothing changes, `--yes` or not.
    let refused = sb.moat(&["policy", "migrate", "--file", path, "--yes"]);
    assert_eq!(refused.status.code(), Some(USAGE), "{}", text(&refused));
    assert!(
        text(&refused).contains("must be run by a person"),
        "{}",
        text(&refused)
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), BY_HAND);

    let out = sb.moat_as_person(&["policy", "migrate", "--file", path, "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let migrated = std::fs::read_to_string(&file).unwrap();
    assert!(migrated.starts_with("# ours\nversion: 1\n"), "{migrated}");
    assert!(migrated.contains("review:\n  - id: deploy"), "{migrated}");
    let kept = std::fs::read_to_string(sb.project().join("policy.yaml.before-migrate")).unwrap();
    assert_eq!(kept, BY_HAND);
    let lint = sb.moat(&["policy", "lint", path]);
    assert_eq!(lint.status.code(), Some(OK), "{}", text(&lint));
}

#[test]
fn the_installed_policy_is_migrated_and_the_lock_re_pinned() {
    let sb = installed();
    let policy = sb.home.join(".moat/policy.yaml");
    let old = std::fs::read_to_string(&policy)
        .unwrap()
        // The key alone, so a CRLF checkout (Windows) matches too.
        .replacen("\nreview:", "\nask:", 1);
    std::fs::write(&policy, &old).unwrap();
    assert!(
        old.contains("\nask:"),
        "the default policy has a top-level `review:`"
    );
    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&accepted).contains("re-pinned"), "{}", text(&accepted));

    let out = sb.moat_as_person(&["policy", "migrate", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    let migrated = std::fs::read_to_string(&policy).unwrap();
    assert!(migrated.contains("\nreview:") && !migrated.contains("\nask:"));
    assert_eq!(
        std::fs::read_to_string(sb.home.join(".moat/policy.yaml.before-migrate")).unwrap(),
        old
    );
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
}
