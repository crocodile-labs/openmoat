use super::*;

/// Once the person let a write of a file run (the file holds what the reviewed
/// write sent, and did not before), the next write of the same file in the
/// same session is answered; a declined write (the file does not hold it)
/// answers nothing, so a retry of it still needs review.
#[test]
fn an_approved_write_covers_the_next_write_of_the_same_file() {
    let t = Covering::new();
    let read = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/".into(),
        },
        Verdict::Allow,
    );
    let taint = Covering::tainted_since(read);
    let write = t.write_of(WORKFLOW);
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // the review is recorded; the person declines, so the file is not written
    t.held_write("s1", &write, "on: push", "");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // the person approves the retry: the agent writes the file
    t.held_write("s1", &write, "on: push", "");
    t.put(WORKFLOW, "on: push");
    let covered = t.decide("s1", &write, &taint);
    assert_eq!(covered.verdict, Verdict::Allow, "{covered:?}");
    assert!(
        covered
            .reasons
            .iter()
            .any(|r| r.contains("an earlier write of") && r.contains(WORKFLOW)),
        "{covered:?}"
    );
    assert!(!covered.rules.iter().any(|r| r == TAINT_RULE));
}

/// The answer covers the one file in the one session, and only until the
/// session reads untrusted content again.
#[test]
fn another_file_session_or_a_later_untrusted_read_is_not_covered() {
    let t = Covering::new();
    let read = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/".into(),
        },
        Verdict::Allow,
    );
    let taint = Covering::tainted_since(read);
    let write = t.write_of(WORKFLOW);
    let approved = t.held_write("s1", &write, "on: push", "");
    t.put(WORKFLOW, "on: push");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Allow);

    // another protected file of the project
    assert_eq!(
        t.decide("s1", &t.write_of("Makefile"), &taint).verdict,
        Verdict::Review
    );
    // the same file from another session
    assert_eq!(t.decide("s2", &write, &taint).verdict, Verdict::Review);
    // more untrusted content after the approved write: it saw none of it
    let later = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/2".into(),
        },
        Verdict::Allow,
    );
    assert!(later.0 > approved.0);
    assert_eq!(
        t.decide("s1", &write, &Covering::tainted_since(later))
            .verdict,
        Verdict::Review
    );
    // the untrusted read in the very row of the write is not before it
    assert_eq!(
        t.decide("s1", &write, &Covering::tainted_since(approved))
            .verdict,
        Verdict::Review
    );
}

/// No evidence that the person approved: a write that would have left the
/// file as it was (a probe with the file's own content, declined or not), an
/// edit whose content the hook never saw, and a file changed since.
#[test]
fn a_write_that_changed_nothing_an_edit_and_a_changed_file_are_not_covered() {
    let t = Covering::new();
    let read = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/".into(),
        },
        Verdict::Allow,
    );
    let taint = Covering::tainted_since(read);
    let write = t.write_of(WORKFLOW);

    // the file already held what the reviewed write sent: declining it changes nothing
    t.put(WORKFLOW, "on: push");
    t.held_write("s1", &write, "on: push", "on: push");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // an edit: the content is not known, so nothing can show it ran
    let edit = t.record("s1", &write, Verdict::Review);
    t.store
        .add_session_writes(
            edit,
            Host::ClaudeCode.id(),
            "s1",
            &[SessionWrite {
                path: format!("{}/{WORKFLOW}", t.proj),
                sha256: None,
                before: None,
            }],
        )
        .unwrap();
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // an approved write, then the file changed by someone else
    t.held_write("s1", &write, "on: pull_request", "on: push");
    t.put(WORKFLOW, "on: pull_request");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Allow);
    t.put(WORKFLOW, "on: workflow_dispatch");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);
}

/// An edit is covered like a write once the file shows it ran: the content it
/// leaves is the file with the replacements applied (Claude Code `Edit`,
/// `MultiEdit`). A declined edit, one whose `old_string` occurs twice (Claude
/// Code refuses it, so its outcome is not known) and a file changed since
/// cover nothing.
#[test]
fn an_approved_edit_covers_the_next_write_of_the_same_file() {
    let t = Covering::new();
    let read = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/".into(),
        },
        Verdict::Allow,
    );
    let taint = Covering::tainted_since(read);
    let write = t.write_of(WORKFLOW);
    t.put(WORKFLOW, "on: push\njobs: {}\n");

    // declined: the file still holds the old text
    t.held_edit("s1", &write, &[("push", "pull_request", false)]);
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // approved: the agent's edit ran, and the file holds the result
    t.held_edit("s1", &write, &[("push", "pull_request", false)]);
    t.put(WORKFLOW, "on: pull_request\njobs: {}\n");
    let covered = t.decide("s1", &write, &taint);
    assert_eq!(covered.verdict, Verdict::Allow, "{covered:?}");
    assert!(
        covered
            .reasons
            .iter()
            .any(|r| r.contains("an earlier write of"))
    );

    // a multi-edit, its second replacement everywhere
    t.put(WORKFLOW, "a b a\n");
    t.held_edit("s1", &write, &[("b", "c", false), ("a", "d", true)]);
    t.put(WORKFLOW, "d c d\n");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Allow);

    // `old_string` occurs twice without `replace_all`: Claude Code refuses the
    // edit, so nothing it could leave is known, whatever the file holds after
    t.put(WORKFLOW, "x\nx\n");
    t.held_edit("s1", &write, &[("x", "y", false)]);
    t.put(WORKFLOW, "y\nx\n");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);

    // approved, then the file changed by someone else
    t.put(WORKFLOW, "one\n");
    t.held_edit("s1", &write, &[("one", "two", false)]);
    t.put(WORKFLOW, "two\n");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Allow);
    t.put(WORKFLOW, "three\n");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Review);
}

/// A taint review from a secret the session read is never answered by a write
/// that ran: the covering applies to writes after untrusted content only.
#[test]
fn a_secret_taint_is_not_answered_by_an_earlier_write() {
    let t = Covering::new();
    let read = t.record(
        "s1",
        &Action::Fetch {
            url: "https://evil.example/".into(),
        },
        Verdict::Allow,
    );
    let mut taint = Covering::tainted_since(read);
    taint.taint.secrets.push(TaintSecret {
        source: "read /home/u/.ssh/id_rsa".to_owned(),
        host: None,
    });
    // the secret does not stop a write of a file the person let run
    let write = t.write_of(WORKFLOW);
    t.held_write("s1", &write, "on: push", "");
    t.put(WORKFLOW, "on: push");
    assert_eq!(t.decide("s1", &write, &taint).verdict, Verdict::Allow);
    // but a fetch to another host needs review for the secret, whatever the session wrote
    let fetch = Action::Fetch {
        url: "https://other.example/".into(),
    };
    let decision = t.decide("s1", &fetch, &taint);
    assert_eq!(decision.verdict, Verdict::Review, "{decision:?}");
    assert!(decision.rules.iter().any(|r| r == TAINT_RULE));
}
