//! `moat allow` and `moat doctor --accept` success paths, end to end.
//!
//! Both commands require a terminal. Debug builds honour `MOAT_ASSUME_TTY=1`
//! (see `terminal.rs`), which these tests set only for the commands a person
//! would type; `guard` runs without it, exactly as a hook does.

use crate::common::{ASK, DENY, OK, Sandbox, USAGE, text};

/// The hook's verdict and reason for one Bash call in the sandbox's project.
fn guard(sb: &Sandbox, session: &str, command: &str) -> (String, String) {
    sb.guard_bash(session, &sb.project(), command)
}

const INSTALL: &str = "npm install left-pad";

#[test]
fn allow_last_grants_the_session_and_repins() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");

    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("session s1 on claude-code may run"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).contains("a new session asks again"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));

    let (verdict, reason) = guard(&sb, "s1", INSTALL);
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("approved-session"), "{reason}");
    assert_eq!(guard(&sb, "s2", INSTALL).0, "ask", "grants are per session");
}

#[test]
fn no_session_grant_for_a_call_without_a_session_id() {
    // A host that sends no session id is recorded as session "unknown", shared
    // by every such call: a "session" grant there would hold everywhere.
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(guard(&sb, "unknown", INSTALL).0, "ask");

    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("no session id"), "{}", text(&out));

    let explicit = [
        "allow",
        INSTALL,
        "--host",
        "claude-code",
        "--session",
        "unknown",
    ];
    let out = sb.moat_as_person(&explicit);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(guard(&sb, "unknown", INSTALL).0, "ask", "still asked");
}

#[test]
fn allow_explicit_session_grant() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let out = sb.moat_as_person(&["allow", INSTALL, "--host", "claude-code", "--session", "s9"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(guard(&sb, "s9", INSTALL).0, "allow");
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");
}

#[test]
fn allow_always_writes_the_overlay_and_keeps_the_lock_intact() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");
    let out = sb.moat_as_person(&["allow", "--last", "--always"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = text(&out);
    assert!(
        shown.contains(&format!(
            "will allow: {INSTALL} (and the same command with extra arguments); \
             deny rules still win"
        )),
        "{shown}"
    );
    assert!(
        shown.contains("undo: moat allow --remove approved-1"),
        "{shown}"
    );

    let overlay = std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml")).unwrap();
    assert!(
        overlay.contains("approved-1") && overlay.contains(INSTALL),
        "{overlay}"
    );

    let (verdict, reason) = guard(&sb, "another-session", INSTALL);
    assert_eq!(
        verdict, "allow",
        "the overlay is re-pinned, not drift: {reason}"
    );
    assert!(reason.contains("approved-1"), "{reason}");
}

#[test]
fn allow_explains_missing_flags_and_shadowed_rules() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let out = sb.moat_as_person(&["allow", "ls"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(
        text(&out).contains("--always for a permanent rule"),
        "{}",
        text(&out)
    );

    // A shell deny pattern shadows the new allow, so the linter names it.
    let out = sb.moat_as_person(&["allow", "git reset --hard", "--always"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("warning: rule `approved-1`") && text(&out).contains("unreachable"),
        "{}",
        text(&out)
    );
    assert_eq!(guard(&sb, "s1", "git reset --hard").0, "deny");
    // A path deny wins over a shell allow too (the linter compares shell rules only).
    assert_eq!(guard(&sb, "s1", "rm -rf /").0, "deny");

    guard(&sb, "s1", INSTALL);
    let out = sb.moat_as_person(&["allow", "--last"]);
    assert!(text(&out).contains("wanted to run"), "{}", text(&out));
}

#[test]
fn doctor_accept_repins_after_a_person_edits_the_policy() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text_now = std::fs::read_to_string(&policy).unwrap();
    text_now.push_str("\n# edited by the owner\n");
    std::fs::write(&policy, text_now).unwrap();
    let (verdict, reason) = guard(&sb, "s1", "git status");
    assert_eq!(verdict, "deny");
    assert!(reason.contains("kernel-integrity"), "{reason}");

    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    assert_eq!(guard(&sb, "s1", "git status").0, "allow");
}

#[test]
fn doctor_accept_refuses_to_pin_a_policy_that_does_not_lint() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let policy = sb.home.join(".moat/policy.yaml");
    std::fs::write(&policy, "version: 1\ndeny:\n  - id: broken\n").unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert_ne!(out.status.code(), Some(OK));
    assert!(
        text(&out).contains("refusing to pin a policy that does not lint"),
        "{}",
        text(&out)
    );
    let (verdict, reason) = guard(&sb, "s1", "git status");
    assert_eq!(verdict, "deny", "the broken edit is still drift: {reason}");
}

#[test]
fn hooks_without_a_terminal_are_still_refused() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let out = sb.moat(&["allow", INSTALL, "--always"]);
    assert_ne!(out.status.code(), Some(OK));
    assert!(text(&out).contains("must be run by a person in a terminal"));
}

/// Bytes of the files `moat allow` writes (`None` when absent).
fn approval_state(sb: &Sandbox) -> Vec<Option<Vec<u8>>> {
    ["policy.d/approved.yaml", "approvals.json", "policy.lock"]
        .iter()
        .map(|f| std::fs::read(sb.home.join(".moat").join(f)).ok())
        .collect()
}

/// Append to a pinned file, then check `allow` with `args` refuses and writes nothing.
fn assert_allow_refuses_after_tampering(pinned: &str, args: &[&str]) {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let path = sb.home.join(pinned);
    let mut tampered = std::fs::read(&path).unwrap();
    // Whitespace alone would not do: a settings file is pinned by its JSON (#287).
    tampered.extend_from_slice(b"\n# tampered\n");
    std::fs::write(&path, tampered).unwrap();
    let before = approval_state(&sb);

    let out = sb.moat_as_person(args);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(USAGE), "{message}");
    assert!(
        message.contains("kernel-integrity") && message.contains("was modified"),
        "{message}"
    );
    assert!(
        message.contains("`moat doctor`") && message.contains("`moat doctor --accept`"),
        "{message}"
    );
    let file = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(message.contains(&file), "names {file}: {message}");
    assert_eq!(approval_state(&sb), before, "nothing written");
    assert_eq!(guard(&sb, "s1", INSTALL).0, "deny", "drift still denies");
}

#[test]
fn allow_always_refuses_over_a_tampered_hook_file() {
    assert_allow_refuses_after_tampering(".claude/settings.json", &["allow", INSTALL, "--always"]);
}

#[test]
fn allow_always_refuses_over_a_tampered_policy() {
    assert_allow_refuses_after_tampering(".moat/policy.yaml", &["allow", INSTALL, "--always"]);
}

#[test]
fn session_grant_refuses_over_a_drifted_lock() {
    let args = ["allow", INSTALL, "--host", "claude-code", "--session", "s1"];
    assert_allow_refuses_after_tampering(".claude/settings.json", &args);
    assert_allow_refuses_after_tampering(".moat/policy.yaml", &args);
}

#[test]
fn allow_on_a_clean_lock_pins_only_the_overlay_it_wrote() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    // Every pin but the overlay's, which is the one file `allow --always` writes.
    let others = |sb: &Sandbox| {
        let lock = std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap();
        let mut lock: serde_json::Value = serde_json::from_str(&lock).unwrap();
        let entries = lock["entries"].as_object_mut().unwrap();
        let overlay = entries
            .keys()
            .find(|k| k.ends_with("approved.yaml"))
            .cloned();
        let overlay = overlay.and_then(|k| entries.remove(&k));
        (entries.clone(), overlay)
    };
    let (before, overlay_before) = others(&sb);
    let out = sb.moat_as_person(&["allow", INSTALL, "--always"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));

    let (after, overlay_after) = others(&sb);
    assert_eq!(after, before, "only the overlay's pin changes");
    assert!(overlay_after.is_some() && overlay_after != overlay_before);
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
}

/// Exit code of `moat policy check` for one action against the installed policy:
/// 0 allow, 2 deny, 3 ask.
fn check(sb: &Sandbox, kind: &str, action: &str) -> Option<i32> {
    let cwd = sb.project();
    let cwd = cwd.to_str().unwrap();
    let out = sb.moat(&["policy", "check", action, "--kind", kind, "--cwd", cwd]);
    out.status.code()
}

#[test]
fn allow_site_adds_a_net_rule_and_remove_takes_it_back() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    assert_eq!(
        check(&sb, "net", "docs.rs"),
        Some(DENY),
        "default.net denies"
    );

    let out = sb.moat_as_person(&["allow", "--site", "Docs.rs"]);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("added to")
            && message.contains("- docs.rs")
            && message.contains("undo: moat allow --remove approved-1")
            && message.contains("lock re-pinned")
            && message.contains("Updating the agents' sandbox settings"),
        "{message}"
    );
    assert_eq!(check(&sb, "net", "docs.rs"), Some(OK));
    assert_eq!(check(&sb, "fetch", "https://docs.rs/serde"), Some(OK));
    assert_eq!(check(&sb, "net", "evil.docs.rs"), Some(DENY), "no wildcard");

    let out = sb.moat_as_person(&["allow", "--remove", "approved-1"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("removed from"), "{}", text(&out));
    assert_eq!(check(&sb, "net", "docs.rs"), Some(DENY));
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));

    let out = sb.moat_as_person(&["allow", "--remove", "approved-1"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("rules there: none"), "{}", text(&out));
}

#[test]
fn allow_site_and_dir_refuse_dangerous_input_and_write_nothing() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let before = approval_state(&sb);
    let home = sb.home.to_str().unwrap().to_owned();
    let root = sb
        .home
        .ancestors()
        .last()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    for (args, says) in [
        (vec!["allow", "--site", "*"], "not a host name"),
        (
            vec!["allow", "--site", "https://evil.com"],
            "not a host name",
        ),
        (vec!["allow", "--dir", &home], "home directory"),
        (vec!["allow", "--dir", &root], "home directory"),
        (vec!["allow", "--dir", "no/such/dir"], "does not exist"),
        (
            vec!["allow", "--site", "x.dev", "--last"],
            "cannot be used with",
        ),
    ] {
        let out = sb.moat_as_person(&args);
        assert_ne!(out.status.code(), Some(OK), "{args:?}");
        assert!(text(&out).contains(says), "{args:?}: {}", text(&out));
    }
    assert_eq!(approval_state(&sb), before, "nothing written");
}

#[test]
fn allow_dir_opens_the_directory_but_deny_rules_still_win() {
    let sb = Sandbox::installed_asking(&[".claude"]);
    let shared = sb.home.join("work/shared");
    std::fs::create_dir_all(&shared).unwrap();
    let notes = shared.join("notes.md").to_str().unwrap().to_owned();
    let env = shared.join(".env").to_str().unwrap().to_owned();
    assert_eq!(
        check(&sb, "fs-write", &notes),
        Some(3),
        "outside the project asks"
    );

    let out = sb.moat_as_person(&["allow", "--dir", shared.to_str().unwrap()]);
    let message = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{message}");
    assert!(
        message.contains("fs.write:")
            && message.contains("/**")
            && message.contains("deny rules still win")
            && message.contains("Updating the agents' sandbox settings"),
        "{message}"
    );
    assert_eq!(check(&sb, "fs-write", &notes), Some(OK));
    let hook = shared.join(".git/hooks/pre-commit");
    assert_ne!(
        check(&sb, "fs-write", hook.to_str().unwrap()),
        Some(OK),
        "a hook planted in the allowed directory is not allowed by it"
    );
    let doctor = sb.moat(&["doctor"]);
    assert!(text(&doctor).contains("all intact"), "{}", text(&doctor));
    assert_eq!(check(&sb, "fs-read", &notes), Some(OK));
    assert_eq!(
        check(&sb, "fs-read", &env),
        Some(2),
        "secrets-paths still denies"
    );
    let sibling = sb.home.join("work/other.md");
    assert_eq!(check(&sb, "fs-write", sibling.to_str().unwrap()), Some(ASK));
}
