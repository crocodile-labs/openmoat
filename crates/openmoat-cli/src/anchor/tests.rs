use std::collections::BTreeMap;
use std::process::Command;

use openmoat_audit::{BreakKind, ChainBreak};

use super::*;

fn record(id: i64, hash: &str) -> Record {
    Record::new(
        &ChainHead {
            id: EventId(id),
            ts_ms: 1_700_000_000_000 + id,
            hash: hash.to_owned(),
        },
        1_800_000_000_000,
    )
}

fn intact() -> ChainReport {
    ChainReport {
        events: 5,
        unchained: 0,
        head: Some("e".into()),
        broken: None,
    }
}

fn log(hashes: &[(i64, &str)]) -> impl Fn(EventId) -> Result<Option<String>> {
    let map: BTreeMap<i64, String> = hashes.iter().map(|(i, h)| (*i, (*h).to_owned())).collect();
    move |id: EventId| Ok(map.get(&id.0).cloned())
}

#[test]
fn records_round_trip_as_lines_and_other_lines_fail() {
    let text = format!(
        "{}\n\n{}\n",
        record(1, "a").line().unwrap(),
        record(4, "d").line().unwrap()
    );
    let records = parse(&text).unwrap();
    assert_eq!(records, [record(1, "a"), record(4, "d")]);
    assert!(
        text.contains("\"format\":\"moat-audit-anchor-v1\""),
        "{text}"
    );
    assert!(text.contains("\"event\":\"4\""), "{text}");
    assert!(parse("").is_err(), "no anchors");
    let extra = text.replace("}\n", ",\"x\":1}\n");
    assert!(parse(&extra).is_err(), "an unknown field");
    assert!(parse("not json\n").is_err());
}

#[test]
fn each_anchor_must_still_be_in_the_log_with_its_hash() {
    let records = [record(1, "a"), record(3, "c")];
    let full = log(&[(1, "a"), (2, "b"), (3, "c"), (4, "d")]);
    assert_eq!(check(&records, &intact(), full).unwrap(), None);

    let truncated = log(&[(1, "a"), (2, "b")]);
    let failed = check(&records, &intact(), truncated).unwrap().unwrap();
    assert_eq!((failed.number, failed.why), (2, Mismatch::Missing));
    assert_eq!(failed.record.event, EventId(3));

    let rewritten = log(&[(1, "x"), (2, "y"), (3, "z")]);
    let failed = check(&records, &intact(), rewritten).unwrap().unwrap();
    assert_eq!((failed.number, failed.why), (1, Mismatch::Rewritten));
}

#[test]
fn a_chain_broken_before_an_anchor_fails_it() {
    let records = [record(1, "a"), record(3, "c")];
    let mut chain = intact();
    chain.broken = Some(ChainBreak {
        id: EventId(2),
        kind: BreakKind::Edited,
    });
    let full = log(&[(1, "a"), (2, "b"), (3, "c")]);
    let failed = check(&records, &chain, full).unwrap().unwrap();
    assert_eq!((failed.number, failed.why), (2, Mismatch::ChainBroken));
}

#[test]
fn a_file_place_appends_one_line_per_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("anchors.txt");
    let place = Place::of(&file);
    assert_eq!(place, Place::File(file.clone()));
    let git = Path::new("git");
    assert_eq!(place.append(&record(1, "a"), git).unwrap(), None);
    place.append(&record(2, "b"), git).unwrap();
    assert_eq!(
        place.records(git).unwrap(),
        [record(1, "a"), record(2, "b")]
    );
    assert_eq!(Place::of(dir.path()), Place::Git(dir.path().to_path_buf()));
}

/// git from the search path, `None` (and the test stops early) without one.
fn git() -> Option<PathBuf> {
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    crate::environment::find_in(&path, &[], "git")
}

#[test]
fn a_git_place_commits_on_its_own_ref_and_leaves_head_alone() {
    let Some(program) = git() else { return };
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let git = |args: &[&str]| {
        let out = Command::new(&program)
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    git(&["config", "user.name", "Pat"]);
    git(&["config", "user.email", "pat@example.com"]);
    let place = Place::Git(repo.to_path_buf());
    assert!(place.records(&program).is_err(), "no ref yet");

    let first = place.append(&record(1, "a"), &program).unwrap().unwrap();
    let second = place.append(&record(2, "b"), &program).unwrap().unwrap();
    assert_eq!(git(&["rev-parse", git::REF]), second);
    assert_eq!(git(&["rev-parse", &format!("{second}^")]), first);
    assert_eq!(
        place.records(&program).unwrap(),
        [record(1, "a"), record(2, "b")]
    );
    let message = git(&["log", "-1", "--format=%B", git::REF]);
    assert!(
        message.contains("Signed-off-by: Pat <pat@example.com>"),
        "{message}"
    );
    assert!(
        message.starts_with("moat audit anchor: event 2"),
        "{message}"
    );
    assert_eq!(
        git(&["status", "--porcelain"]),
        "",
        "the work tree is untouched"
    );
    let branches = git(&["for-each-ref", "refs/heads"]);
    assert_eq!(branches, "", "no branch was made");

    let plain = tempfile::tempdir().unwrap();
    let error = git::Repo::new(&program, plain.path()).err().unwrap();
    assert!(
        error.to_string().contains("not a git repository"),
        "{error}"
    );
}
