//! Agent provenance (ADR-056) on a fixture audit store: who wrote what, after
//! reading what; notes round-trip and verify; tampering shows; check-diff's
//! section renders in every format.

use openmoat_audit::{EventId, NewEvent, NewProvenance, ProvenanceKind, SessionWrite, Store};
use openmoat_core::attribution::{
    ChangedFile, Evidence, FileRecord, LineRange, Untrusted, attribute, summarise,
};
use openmoat_core::{
    Action, CompiledPolicy, Decision, EvalContext, Policy, UntrustedKind, Verdict,
};

use super::collect::{self, CommitFacts, Root};
use super::{notes, review};

const POLICY: &str = "version: 1\ndefaults: { \"*\": allow }\n";

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: Some("/repo".to_owned()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/repo".to_owned(),
        case_insensitive_paths: false,
    }
}

fn call(store: &Store, session: &str, action: &Action) -> EventId {
    let decision = Decision::new(Verdict::Allow);
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: session,
            call_id: None,
            cwd: Some("/repo"),
            tool: "tool",
            action: Some(action),
            decision: &decision,
            latency_us: 0,
        })
        .unwrap()
}

fn fetch(store: &Store, session: &str) -> EventId {
    let action = Action::Fetch {
        url: "https://evil.example/issue".to_owned(),
    };
    call(store, session, &action)
}

/// A write of `/repo/<path>` by `session`, recorded as the guard records it.
fn wrote(store: &Store, session: &str, path: &str, hashes: Option<(&str, &str)>) -> EventId {
    let abs = format!("/repo/{path}");
    let id = call(store, session, &Action::FsWrite { path: abs.clone() });
    let write = SessionWrite {
        path: abs,
        sha256: hashes.map(|h| h.1.to_owned()),
        before: hashes.map(|h| h.0.to_owned()),
    };
    store
        .add_session_writes(id, "claude-code", session, &[write])
        .unwrap();
    id
}

fn tainted_row(store: &Store, event: EventId, session: &str, path: &str) {
    let row = NewProvenance {
        kind: ProvenanceKind::TaintedWrite,
        path: format!("/repo/{path}"),
        sha256: None,
        source: "which session x wrote after it read untrusted content".to_owned(),
    };
    store
        .add_provenance(event, "claude-code", session, &[row])
        .unwrap();
}

fn file(path: &str, before: &str, after: &str) -> ChangedFile {
    ChangedFile {
        path: path.to_owned(),
        before: Some(before.to_owned()),
        after: Some(after.to_owned()),
        added: vec![LineRange { start: 1, end: 4 }],
    }
}

fn facts(files: Vec<ChangedFile>) -> CommitFacts {
    let now = crate::time::now_ms();
    CommitFacts {
        commit: "c".repeat(40),
        parent_ms: Some(now - 600_000),
        commit_ms: now + 60_000,
        files,
    }
}

/// The fixture: s1 fetched a page, then made the whole change to `a.rs`;
/// s2 wrote `b.sh` by a shell write (no hash) and read nothing untrusted;
/// s3 wrote `c.md` after reading a tainted file (only the hook's row says
/// so); s4 wrote `d.rs` and fetched only afterwards; s5 wrote outside the
/// repository.
fn fixture() -> (Store, CommitFacts) {
    let store = Store::open_in_memory().unwrap();
    fetch(&store, "s1");
    wrote(&store, "s1", "src/a.rs", Some(("h0", "h1")));
    wrote(&store, "s2", "b.sh", None);
    let c = wrote(&store, "s3", "c.md", None);
    tainted_row(&store, c, "s3", "c.md");
    wrote(&store, "s4", "d.rs", Some(("", "hd")));
    fetch(&store, "s4");
    let outside = call(
        &store,
        "s5",
        &Action::FsWrite {
            path: "/elsewhere/src/a.rs".into(),
        },
    );
    let write = SessionWrite {
        path: "/elsewhere/src/a.rs".into(),
        sha256: Some("h1".into()),
        before: Some("h0".into()),
    };
    store
        .add_session_writes(outside, "claude-code", "s5", &[write])
        .unwrap();
    let commit = facts(vec![
        file("src/a.rs", "h0", "h1"),
        file("b.sh", "x", "y"),
        file("c.md", "x", "z"),
        file("d.rs", "", "hd"),
        file("untouched.rs", "x", "y"),
    ]);
    (store, commit)
}

fn attributed(store: &Store, commit: &CommitFacts) -> Vec<FileRecord> {
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let root = Root::new("/repo", None, false);
    let writes = collect::writes(
        store,
        &compiled,
        &root,
        std::slice::from_ref(commit),
        commit.commit_ms,
    )
    .unwrap();
    attribute(&commit.as_commit(), &writes)
}

#[test]
fn each_file_is_attributed_to_its_session_with_what_it_had_read() {
    let (store, commit) = fixture();
    let found = attributed(&store, &commit);
    let seen: Vec<(&str, &str, Evidence, Option<UntrustedKind>)> = found
        .iter()
        .map(|f| {
            (
                f.path.as_str(),
                f.session.as_str(),
                f.evidence,
                f.untrusted.as_ref().map(|u| u.kind),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("b.sh", "s2", Evidence::Touched, None),
            ("c.md", "s3", Evidence::Touched, Some(UntrustedKind::File)),
            ("d.rs", "s4", Evidence::Lines, None),
            ("src/a.rs", "s1", Evidence::Lines, Some(UntrustedKind::Web)),
        ]
    );
    let a = found.iter().find(|f| f.path == "src/a.rs").unwrap();
    assert_eq!(a.line_count(), 4);
    assert!(
        a.untrusted
            .as_ref()
            .unwrap()
            .source
            .contains("evil.example"),
        "{a:?}"
    );
}

#[test]
fn a_repository_reached_through_a_link_or_another_case_still_matches() {
    let store = Store::open_in_memory().unwrap();
    wrote(&store, "s1", "src/a.rs", Some(("h0", "h1")));
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    let commit = facts(vec![file("src/a.rs", "h0", "h1")]);
    let commits = std::slice::from_ref(&commit);
    // git names the root through a link; the hook recorded the real path
    let linked = Root::new("/link/to/repo", Some("/repo"), false);
    assert_eq!(
        collect::writes(&store, &compiled, &linked, commits, commit.commit_ms)
            .unwrap()
            .len(),
        1
    );
    // where paths ignore case, the hook keeps them lowercased
    let store = Store::open_in_memory().unwrap();
    wrote(&store, "s1", "src/a.rs", Some(("h0", "h1")));
    let commit = facts(vec![file("SRC/A.rs", "h0", "h1")]);
    let found = collect::writes(
        &store,
        &compiled,
        &Root::new("/REPO", None, true),
        std::slice::from_ref(&commit),
        commit.commit_ms,
    )
    .unwrap();
    assert_eq!(found[0].path, "SRC/A.rs");
    // another repository's file of the same name is not this one's
    let other = Root::new("/other", None, false);
    let found = collect::writes(&store, &compiled, &other, commits, commit.commit_ms).unwrap();
    assert_eq!(found.len(), 0, "{found:?}");
}

#[test]
fn a_note_round_trips_and_verifies_against_the_log_it_came_from() {
    let (store, commit) = fixture();
    let found = attributed(&store, &commit);
    let note = notes::build(&store, &commit.commit, found.clone()).unwrap();
    assert_eq!(note.events.len(), found.len());
    assert!(note.events.iter().all(|e| e.hash.len() == 64));
    let text = notes::encode(&note).unwrap();
    assert!(!text.contains('\n'), "one line");
    let back = notes::decode(&text).unwrap();
    assert_eq!(back, note);
    let chain = store.verify_chain().unwrap();
    let problems = notes::verify(&store, &chain, &commit.commit, &back, &found).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    // unknown fields and formats are refused
    assert!(notes::decode(&text.replacen('{', "{\"extra\":1,", 1)).is_err());
    assert!(notes::decode(&text.replace("provenance-v1", "provenance-v9")).is_err());
}

fn problems_of(
    edit: impl FnOnce(&mut openmoat_core::attribution::Note),
    redigest: bool,
) -> Vec<String> {
    let (store, commit) = fixture();
    let found = attributed(&store, &commit);
    let mut note = notes::build(&store, &commit.commit, found.clone()).unwrap();
    edit(&mut note);
    if redigest {
        note.digest = notes::digest(&note);
    }
    let chain = store.verify_chain().unwrap();
    notes::verify(&store, &chain, &commit.commit, &note, &found).unwrap()
}

#[test]
fn verify_finds_every_kind_of_tampering() {
    let any = |problems: &[String], text: &str| problems.iter().any(|p| p.contains(text));
    // edited without recomputing the digest
    let p = problems_of(|n| n.files[0].session = "s9".into(), false);
    assert!(any(&p, "digest does not match"), "{p:?}");
    // the taint laundered away, digest recomputed: the log still says so
    let p = problems_of(
        |n| {
            for f in &mut n.files {
                f.untrusted = None;
            }
        },
        true,
    );
    assert!(any(&p, "untrusted content"), "{p:?}");
    // a session left out
    let p = problems_of(|n| n.files.retain(|f| f.session != "s1"), true);
    assert!(
        any(&p, "leaves out that claude-code session s1 wrote src/a.rs"),
        "{p:?}"
    );
    // a cited event with a made-up hash
    let p = problems_of(|n| n.events[0].hash = "0".repeat(64), true);
    assert!(any(&p, "not in this log with that hash"), "{p:?}");
    // a head from another log
    let p = problems_of(|n| n.head.hash = "f".repeat(64), true);
    assert!(any(&p, "no longer holds the head"), "{p:?}");
    // a claim pinned on another session's event
    let p = problems_of(
        |n| {
            let other = n.files[1].event;
            n.files[0].event = other;
        },
        true,
    );
    assert!(any(&p, "is not a call of"), "{p:?}");
    // the note of another commit copied onto this one
    let p = problems_of(|n| n.commit = "d".repeat(40), true);
    assert!(any(&p, "names another commit"), "{p:?}");
}

#[test]
fn a_rewritten_log_no_longer_verifies_an_older_note() {
    let (store, commit) = fixture();
    let found = attributed(&store, &commit);
    let note = notes::build(&store, &commit.commit, found.clone()).unwrap();
    // the same claims against a fresh log: none of the cited rows is there
    let (other, _) = fixture();
    fetch(&other, "pad");
    let chain = other.verify_chain().unwrap();
    let problems = notes::verify(&other, &chain, &commit.commit, &note, &found).unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.contains("not in this log") || p.contains("head")),
        "{problems:?}"
    );
}

/// A stand-in for check-diff's report.
#[derive(serde::Serialize)]
struct Report {
    result: &'static str,
}

fn section() -> review::Section {
    let (store, commit) = fixture();
    let note = notes::build(&store, &commit.commit, attributed(&store, &commit)).unwrap();
    review::Section {
        level: "review",
        noted_commits: 1,
        commits: 2,
        unreadable: Vec::new(),
        sessions: summarise(&[note]),
        error: None,
    }
}

#[test]
fn check_diff_shows_who_wrote_what_after_reading_what() {
    let section = section();
    let lines = review::lines(&section);
    assert!(
        lines.contains(
            &"1 file / 4 lines written by claude-code (session s1, after reading web content \
              (fetch evil.example))"
                .to_owned()
        ),
        "{lines:?}"
    );
    assert!(lines.contains(&"1 file written by claude-code (session s2)".to_owned()));
    let mut text = Vec::new();
    review::text(&mut text, &section).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.starts_with("review  provenance: "), "{text}");
    assert!(text.contains("1 of 2 commits have a note on refs/notes/openmoat"));
    assert!(text.contains("a commit without one proves nothing"));
    let annotations = review::annotations(&section);
    assert!(
        annotations
            .iter()
            .all(|a| a.starts_with("::warning title=OpenMoat provenance::"))
    );
    let info = review::Section {
        level: "info",
        ..section.clone()
    };
    assert!(
        review::annotations(&info)
            .iter()
            .all(|a| a.starts_with("::notice "))
    );
    assert_eq!(annotations.len(), section.sessions.len());
    // JSON: check-diff's own keys unchanged, the section beside them
    let value = serde_json::to_value(review::WithSection {
        report: &Report { result: "clean" },
        provenance: &section,
    })
    .unwrap();
    assert_eq!(value["result"], "clean");
    assert_eq!(value["provenance"]["level"], "review");
    assert_eq!(value["provenance"]["sessions"][0]["host"], "claude-code");
}

#[test]
fn a_note_s_text_cannot_inject_workflow_commands() {
    let mut section = section();
    section.sessions[0].untrusted = Some(Untrusted {
        kind: UntrustedKind::Web,
        source: "x\n::error::forged".to_owned(),
    });
    for line in review::annotations(&section) {
        assert!(!line.contains('\n'), "{line}");
    }
    let mut text = Vec::new();
    review::text(&mut text, &section).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(!text.contains("\n::error"), "{text}");
}

#[test]
fn provenance_off_or_without_a_base_shows_nothing() {
    use crate::cli::ProvenanceLevel;
    assert_eq!(
        review::section(Some("main"), None, ProvenanceLevel::Off),
        None
    );
    assert_eq!(review::section(None, None, ProvenanceLevel::Review), None);
}
