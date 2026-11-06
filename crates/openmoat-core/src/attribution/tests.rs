//! Attribution (ADR-056): content matches beat time, a whole change claims
//! its lines, writes after the commit or before the parent do not count, and
//! a note's digest input and comparison catch an edited note.

use super::*;

const PARENT: i64 = 1_000_000;
const COMMIT: i64 = 2_000_000;

fn write(path: &str, session: &str, event: i64, ts_ms: i64) -> AgentWrite {
    AgentWrite {
        path: path.to_owned(),
        host: "claude-code".to_owned(),
        session: session.to_owned(),
        event,
        ts_ms,
        sha256: None,
        before: None,
        untrusted: None,
    }
}

fn hashed(mut w: AgentWrite, before: &str, after: &str) -> AgentWrite {
    w.before = Some(before.to_owned());
    w.sha256 = Some(after.to_owned());
    w
}

fn file(path: &str, before: &str, after: &str) -> ChangedFile {
    ChangedFile {
        path: path.to_owned(),
        before: Some(before.to_owned()),
        after: Some(after.to_owned()),
        added: vec![LineRange { start: 3, end: 5 }],
    }
}

fn commit(files: &[ChangedFile]) -> Commit<'_> {
    Commit {
        parent_ms: Some(PARENT),
        commit_ms: COMMIT,
        files,
    }
}

#[test]
fn a_write_that_made_the_whole_change_claims_the_added_lines() {
    let files = [file("src/a.rs", "h0", "h1")];
    let writes = [hashed(write("src/a.rs", "s1", 7, PARENT + 10), "h0", "h1")];
    let found = attribute(&commit(&files), &writes);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].evidence, Evidence::Lines);
    assert_eq!(found[0].lines, [LineRange { start: 3, end: 5 }]);
    assert_eq!(found[0].line_count(), 3);
    assert_eq!((found[0].event, found[0].session.as_str()), (7, "s1"));
}

#[test]
fn a_write_that_left_the_committed_content_from_another_start_claims_no_lines() {
    let files = [file("src/a.rs", "h0", "h2")];
    // the session edited h1 (a person's change after the parent) into h2
    let writes = [hashed(write("src/a.rs", "s1", 7, PARENT + 10), "h1", "h2")];
    let found = attribute(&commit(&files), &writes);
    assert_eq!(found[0].evidence, Evidence::Content);
    assert_eq!(found[0].lines.len(), 0);
}

#[test]
fn a_content_match_counts_even_before_the_parent_commit() {
    // written long ago, committed only now: the content is still the agent's
    let files = [file("a.txt", "h0", "h1")];
    let writes = [hashed(
        write("a.txt", "s1", 2, PARENT - 500_000),
        "h0",
        "h1",
    )];
    assert_eq!(
        attribute(&commit(&files), &writes)[0].evidence,
        Evidence::Lines
    );
}

#[test]
fn a_write_without_a_hash_counts_only_between_the_parent_and_the_commit() {
    let files = [file("a.sh", "h0", "h1")];
    let between = [write("a.sh", "s1", 3, PARENT + 1)];
    assert_eq!(
        attribute(&commit(&files), &between)[0].evidence,
        Evidence::Touched
    );
    let before_parent = [write("a.sh", "s1", 3, PARENT - 1)];
    assert_eq!(attribute(&commit(&files), &before_parent).len(), 0);
    // a write after the commit (and its slack) cannot be in it
    let after = [hashed(
        write("a.sh", "s1", 3, COMMIT + CLOCK_SLACK_MS + 1),
        "h0",
        "h1",
    )];
    assert_eq!(attribute(&commit(&files), &after).len(), 0);
    // a hash that does not match falls back to time
    let other = [hashed(write("a.sh", "s1", 3, PARENT + 1), "h0", "hx")];
    assert_eq!(
        attribute(&commit(&files), &other)[0].evidence,
        Evidence::Touched
    );
}

#[test]
fn a_root_commit_counts_every_earlier_write_and_new_files_match_from_no_file() {
    let files = [file("new.rs", "", "h1")];
    let root = Commit {
        parent_ms: None,
        commit_ms: COMMIT,
        files: &files,
    };
    let writes = [hashed(write("new.rs", "s1", 1, 5), "", "h1")];
    assert_eq!(attribute(&root, &writes)[0].evidence, Evidence::Lines);
    let unhashed = [write("new.rs", "s1", 1, 5)];
    assert_eq!(attribute(&root, &unhashed)[0].evidence, Evidence::Touched);
}

#[test]
fn each_session_s_newest_write_counts_and_other_files_do_not() {
    let files = [file("a.rs", "h0", "h1")];
    let mut tainted = write("a.rs", "s2", 9, PARENT + 5);
    tainted.untrusted = Some(Untrusted {
        kind: UntrustedKind::Web,
        source: "fetch evil.example".to_owned(),
    });
    let writes = [
        write("a.rs", "s1", 4, PARENT + 2),
        hashed(write("a.rs", "s1", 6, PARENT + 3), "h0", "h1"),
        tainted,
        write("b.rs", "s3", 8, PARENT + 4),
    ];
    let found = attribute(&commit(&files), &writes);
    let seen: Vec<(&str, i64, Evidence)> = found
        .iter()
        .map(|f| (f.session.as_str(), f.event, f.evidence))
        .collect();
    assert_eq!(
        seen,
        [("s1", 6, Evidence::Lines), ("s2", 9, Evidence::Touched)]
    );
    assert_eq!(
        found[1].untrusted.as_ref().map(|u| u.kind),
        Some(UntrustedKind::Web)
    );
}

#[test]
fn a_deleted_or_unreadable_file_is_only_ever_touched() {
    let deleted = [ChangedFile {
        path: "gone.rs".to_owned(),
        before: Some("h0".to_owned()),
        after: Some(String::new()),
        added: Vec::new(),
    }];
    let writes = [hashed(write("gone.rs", "s1", 1, PARENT + 1), "h0", "")];
    assert_eq!(
        attribute(&commit(&deleted), &writes)[0].evidence,
        Evidence::Touched
    );
    let unknown = [ChangedFile {
        path: "big.bin".to_owned(),
        ..ChangedFile::default()
    }];
    let writes = [hashed(write("big.bin", "s1", 1, PARENT + 1), "", "h1")];
    assert_eq!(
        attribute(&commit(&unknown), &writes)[0].evidence,
        Evidence::Touched
    );
}

#[test]
fn added_lines_are_read_from_zero_context_hunks() {
    let patch = "diff --git a/src/a.rs b/src/a.rs\n\
                 index 1..2 100644\n\
                 --- a/src/a.rs\n\
                 +++ b/src/a.rs\n\
                 @@ -1,0 +2,3 @@ fn main\n\
                 +x\n+y\n+z\n\
                 @@ -9 +12 @@\n\
                 -old\n+new\n\
                 @@ -20,2 +22,0 @@\n\
                 diff --git a/gone b/gone\n\
                 --- a/gone\n\
                 +++ /dev/null\n\
                 @@ -1 +0,0 @@\n\
                 diff --git \"a/t\\tab\" \"b/t\\tab\"\n\
                 +++ \"b/t\\tab\"\n\
                 @@ -0,0 +1 @@\n";
    let lines = added_lines(patch);
    assert_eq!(
        lines.get("src/a.rs").unwrap(),
        &[
            LineRange { start: 2, end: 4 },
            LineRange { start: 12, end: 12 }
        ]
    );
    assert_eq!(lines.len(), 1, "{lines:?}");
}

fn note(files: Vec<FileRecord>) -> Note {
    Note {
        format: NoteFormat::V1,
        commit: "c0ffee".to_owned(),
        head: AuditHead {
            event: 10,
            hash: "aa".to_owned(),
        },
        events: vec![EventHash {
            event: 7,
            hash: "bb".to_owned(),
        }],
        digest: String::new(),
        files,
    }
}

fn record(session: &str, untrusted: Option<UntrustedKind>) -> FileRecord {
    FileRecord {
        path: "src/a.rs".to_owned(),
        host: "claude-code".to_owned(),
        session: session.to_owned(),
        event: 7,
        ts_ms: PARENT + 10,
        evidence: Evidence::Lines,
        lines: vec![LineRange { start: 3, end: 5 }],
        untrusted: untrusted.map(|kind| Untrusted {
            kind,
            source: "fetch x.example".to_owned(),
        }),
    }
}

#[test]
fn every_claim_changes_the_digest_input() {
    let base = note(vec![record("s1", Some(UntrustedKind::Web))]);
    let input = base.digest_input();
    assert_eq!(input, base.clone().digest_input(), "deterministic");
    let mut changes = Vec::new();
    let mut n = base.clone();
    n.files[0].untrusted = None;
    changes.push(n);
    let mut n = base.clone();
    n.files[0].evidence = Evidence::Touched;
    changes.push(n);
    let mut n = base.clone();
    n.files[0].lines.clear();
    changes.push(n);
    let mut n = base.clone();
    n.files[0].session = "s9".to_owned();
    changes.push(n);
    let mut n = base.clone();
    n.events[0].hash = "cc".to_owned();
    changes.push(n);
    let mut n = base.clone();
    n.head.event = 11;
    changes.push(n);
    let mut n = base.clone();
    n.files.clear();
    changes.push(n);
    for changed in changes {
        assert_ne!(changed.digest_input(), input, "{changed:?}");
    }
    // the digest itself is not part of what it covers
    let mut n = base;
    n.digest = "ff".to_owned();
    assert_eq!(n.digest_input(), input);
}

#[test]
fn a_note_that_hides_a_session_or_its_taint_differs_from_the_log() {
    let found = [record("s1", Some(UntrustedKind::Web)), record("s2", None)];
    assert_eq!(compare(&found, &found), Vec::<Discrepancy>::new());
    let hidden = compare(&found[..1], &found);
    assert_eq!(
        hidden,
        [Discrepancy::Omitted {
            path: "src/a.rs".to_owned(),
            host: "claude-code".to_owned(),
            session: "s2".to_owned(),
        }]
    );
    let laundered = [record("s1", None), record("s2", None)];
    assert!(matches!(
        compare(&laundered, &found).as_slice(),
        [Discrepancy::Changed { what, .. }] if what.contains("untrusted")
    ));
    let mut weaker = found.clone();
    weaker[0].evidence = Evidence::Touched;
    weaker[0].lines.clear();
    assert_eq!(compare(&weaker, &found).len(), 1);
    // a claim the log can no longer recompute is not a discrepancy
    assert_eq!(compare(&found, &found[..1]), Vec::<Discrepancy>::new());
}

#[test]
fn summaries_count_files_lines_commits_and_the_first_untrusted_read() {
    let mut a = note(vec![record("s1", None)]);
    a.commit = "c1".to_owned();
    let mut later = record("s1", Some(UntrustedKind::Mcp));
    later.path = "src/b.rs".to_owned();
    later.event = 12;
    let mut b = note(vec![record("s1", None), later, record("s2", None)]);
    b.commit = "c2".to_owned();
    let sums = summarise(&[a, b]);
    assert_eq!(sums.len(), 2);
    let s1 = &sums[0];
    assert_eq!((s1.files, s1.lines, s1.commits), (2, 9, 2));
    assert_eq!(
        s1.untrusted.as_ref().map(|u| u.kind),
        Some(UntrustedKind::Mcp)
    );
    assert_eq!(
        (sums[1].session.as_str(), sums[1].untrusted.is_none()),
        ("s2", true)
    );
}
