//! `openmoat allow --for` and `--prune`: standing grants that end, end to end.
//!
//! The binary reads the real clock, so a grant that must end is given `--for 1s`
//! and the test waits a little over two seconds (the end is rounded up to the
//! second); nothing here waits longer.

use std::time::Duration;

use crate::common::{DENY, OK, Sandbox, json, text};

/// Exit code of `openmoat policy check` for one action against the installed
/// policy: 0 allow, 2 deny, 3 review.
fn check(sb: &Sandbox, kind: &str, action: &str) -> Option<i32> {
    let cwd = sb.project();
    let cwd = cwd.to_str().unwrap();
    let out = sb.moat(&["policy", "check", action, "--kind", kind, "--cwd", cwd]);
    out.status.code()
}

/// Long enough for a `--for 1s` grant to have ended.
fn wait_past_one_second() {
    std::thread::sleep(Duration::from_millis(2_200));
}

#[test]
fn a_site_allowed_for_a_while_ends_and_the_call_is_back_to_its_decision() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    assert_eq!(
        check(&sb, "net", "docs.rs"),
        Some(DENY),
        "default.net denies"
    );

    let out = sb.moat_as_person(&["allow", "--site", "docs.rs", "--for", "1h"]);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("added to") && message.contains("ends ") && message.contains("--prune"),
        "{message}"
    );
    assert_eq!(check(&sb, "net", "docs.rs"), Some(OK));
    assert_eq!(check(&sb, "fetch", "https://docs.rs/serde"), Some(OK));
    let listed = json(&sb.moat(&["allowed", "--format", "json"]));
    assert_eq!(
        listed["expires"]["approved-1"]["in_force"], true,
        "{listed}"
    );

    // Granting it again replaces the end: an hour becomes one second.
    let out = sb.moat_as_person(&["allow", "--site", "docs.rs", "--for", "1s"]);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(message.contains("updated in"), "{message}");
    let listed = json(&sb.moat(&["allowed", "--format", "json"]));
    assert_eq!(listed["rules"].as_array().unwrap().len(), 1, "{listed}");

    wait_past_one_second();
    assert_eq!(
        check(&sb, "net", "docs.rs"),
        Some(DENY),
        "an ended grant is left out: back to default.net"
    );
    assert_eq!(check(&sb, "fetch", "https://docs.rs/serde"), Some(DENY));
    let listed = sb.moat(&["allowed"]);
    assert!(
        text(&listed).contains("EXPIRED") && text(&listed).contains("allow --prune"),
        "{}",
        text(&listed)
    );
    let listed = json(&sb.moat(&["allowed", "--format", "json"]));
    assert_eq!(
        listed["expires"]["approved-1"]["in_force"], false,
        "{listed}"
    );
    let status = sb.moat(&["status"]);
    assert!(text(&status).contains("expired"), "{}", text(&status));
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("allow --prune"), "{}", text(&doctor));

    let out = sb.moat_as_person(&["allow", "--prune"]);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("removed from")
            && message.contains("docs.rs")
            && message.contains("lock re-pinned"),
        "{message}"
    );
    let listed = json(&sb.moat(&["allowed", "--format", "json"]));
    assert!(listed["rules"].as_array().unwrap().is_empty(), "{listed}");
    let overlay = std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml")).unwrap();
    assert!(
        overlay.contains("version: 1") && !overlay.contains("expires"),
        "{overlay}"
    );
    let out = sb.moat_as_person(&["allow", "--prune"]);
    assert!(text(&out).contains("nothing to prune"), "{}", text(&out));
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
}

#[test]
fn a_directory_and_a_command_allowed_for_a_while_end_too() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    let shared = sb.home.join("work/shared");
    std::fs::create_dir_all(&shared).unwrap();
    let notes = shared.join("notes.md").to_str().unwrap().to_owned();
    assert_eq!(check(&sb, "fs-write", &notes), Some(3));

    let out = sb.moat_as_person(&["allow", "--dir", shared.to_str().unwrap(), "--for", "1s"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let out = sb.moat_as_person(&["allow", "npm install left-pad", "--always", "--for", "1s"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let (verdict, _) = sb.guard_bash("s1", &sb.project(), "npm install left-pad");
    assert_eq!(verdict, "allow", "in force right after it is given");

    wait_past_one_second();
    assert_eq!(check(&sb, "fs-write", &notes), Some(3), "back to review");
    let (verdict, _) = sb.guard_bash("s1", &sb.project(), "npm install left-pad");
    assert_eq!(verdict, "ask", "the hook's decision is back to review");
}

#[test]
fn an_end_that_cannot_be_read_counts_as_ended() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    let overlay = sb.home.join(".moat/policy.d/approved.yaml");
    std::fs::write(
        &overlay,
        "version: 2\nallow:\n  - id: approved-1\n    net: [docs.rs]\n  - id: approved-2\n    \
         net: [crates.io]\nexpires:\n  approved-1:\n    from: 2026-01-01T00:00:00Z\n    \
         until: next week\n  approved-2: forever\n",
    )
    .unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    assert_eq!(check(&sb, "net", "docs.rs"), Some(DENY));
    assert_eq!(check(&sb, "net", "crates.io"), Some(DENY));
    let listed = sb.moat(&["allowed"]);
    assert!(
        text(&listed).contains("cannot be read"),
        "{}",
        text(&listed)
    );
}

#[test]
fn for_is_refused_where_it_cannot_apply() {
    let sb = Sandbox::installed_with_review(&[".claude"]);
    for (args, says) in [
        (
            vec![
                "allow",
                "make",
                "--host",
                "claude-code",
                "--session",
                "s1",
                "--for",
                "1h",
            ],
            "cannot be used with",
        ),
        (
            vec!["allow", "make", "--for", "1h"],
            "--for ends an --always",
        ),
        (
            vec!["allow", "--site", "docs.rs", "--for", "0h"],
            "cannot read `0h`",
        ),
        (
            vec!["allow", "--site", "docs.rs", "--for", "400d"],
            "at most 366 days",
        ),
        (
            vec!["allow", "--prune", "--site", "docs.rs"],
            "cannot be used with",
        ),
    ] {
        let out = sb.moat_as_person(&args);
        assert_ne!(out.status.code(), Some(OK), "{args:?}");
        assert!(text(&out).contains(says), "{args:?}: {}", text(&out));
    }
    assert_eq!(check(&sb, "net", "docs.rs"), Some(DENY), "nothing written");
}
