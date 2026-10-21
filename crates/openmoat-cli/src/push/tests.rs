use openmoat_audit::KnownSecrets;
use openmoat_core::{Decision, Push, Verdict};

use super::testrepo::{Repo, fake_token, snapshot};
use super::{RUNS_LATER_RULE, SECRET_RULE, UNCHECKED_RULE};
use crate::environment::Snapshot;

/// [`super::check`] with the `git` of this test's search path pinned.
fn check(pushes: &[Push], known: &KnownSecrets, tainted: bool, decision: Decision) -> Decision {
    super::check(pushes, &snapshot(), known, tainted, decision)
}

fn push(repo: &Repo, cmd: &str) -> Vec<Push> {
    vec![Push {
        argv: cmd.split(' ').map(str::to_owned).collect(),
        dirs: vec![Some(repo.dir())],
    }]
}

fn allowed() -> Decision {
    Decision::single(Verdict::Allow, "dev-shell", "git push is allowed")
}

fn checked(repo: &Repo, tainted: bool) -> Decision {
    check(
        &push(repo, "git push"),
        &KnownSecrets::default(),
        tainted,
        allowed(),
    )
}

#[test]
fn a_push_of_ordinary_commits_keeps_its_decision() {
    let repo = Repo::new();
    repo.commit("src/lib.rs", "pub fn f() {}\n", "code");
    assert_eq!(checked(&repo, true), allowed());
    let deferred = Decision::new(Verdict::Defer);
    assert_eq!(
        check(
            &push(&repo, "git push"),
            &KnownSecrets::default(),
            true,
            deferred.clone()
        ),
        deferred
    );
}

#[test]
fn a_token_in_the_newest_commit_denies_without_naming_it() {
    let repo = Repo::new();
    repo.commit(
        "conf/app.env",
        &format!("TOKEN={}\n", fake_token()),
        "config",
    );
    let d = checked(&repo, false);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, [SECRET_RULE]);
    assert!(
        d.reasons[0].contains("adds a GitHub token to conf/app.env"),
        "{d:?}"
    );
    assert!(!format!("{d:?}").contains(&fake_token()));
    assert_eq!(d.context, ["git push is allowed"]);
}

#[test]
fn a_token_added_and_removed_inside_the_push_still_denies() {
    let repo = Repo::new();
    repo.commit("k.txt", &format!("{}\n", fake_token()), "add");
    repo.commit("k.txt", "gone\n", "remove");
    repo.commit("other.txt", "x\n", "later");
    assert_eq!(checked(&repo, false).verdict, Verdict::Deny);
}

#[test]
fn a_token_already_on_the_remote_is_not_the_pushes() {
    let repo = Repo::new();
    repo.commit("k.txt", &format!("{}\n", fake_token()), "add");
    repo.git(&["push", "-q"]);
    repo.commit("k.txt", "gone\n", "remove");
    assert_eq!(checked(&repo, false), allowed());
}

#[test]
fn a_brokered_value_or_a_token_in_a_message_denies() {
    // Generated for the test; no real secret is used.
    let fake = "q7Zp-fake-9xK2mW4v";
    let repo = Repo::new();
    repo.commit("notes.md", &format!("use {fake}\n"), "notes");
    let known = KnownSecrets::new([fake]).unwrap();
    let d = check(&push(&repo, "git push"), &known, false, allowed());
    assert_eq!(d.rules, [SECRET_RULE]);
    assert!(d.reasons[0].contains("brokered secret"), "{d:?}");

    let repo = Repo::new();
    repo.commit("a.txt", "a\n", &format!("rotate {}", fake_token()));
    let d = checked(&repo, false);
    assert!(d.reasons[0].contains("the message of commit"), "{d:?}");
}

#[test]
fn a_workflow_change_asks_only_in_a_tainted_session() {
    let repo = Repo::new();
    repo.commit(".github/workflows/ci.yml", "on: push\n", "ci");
    assert_eq!(checked(&repo, false), allowed());
    let d = checked(&repo, true);
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, [RUNS_LATER_RULE]);
    assert!(d.reasons[0].contains(".github/workflows/ci.yml"), "{d:?}");
}

#[test]
fn a_push_too_large_to_read_or_in_an_unknown_place_asks() {
    let repo = Repo::new();
    let line = "abcdefghij".repeat(10) + "\n";
    repo.commit("big.txt", &line.repeat(90_000), "big");
    let d = checked(&repo, false);
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, [UNCHECKED_RULE]);
    assert!(d.reasons[0].contains("more than 8 MiB"), "{d:?}");

    let unknown = vec![Push {
        argv: vec!["git".into(), "push".into()],
        dirs: vec![None],
    }];
    let d = check(&unknown, &KnownSecrets::default(), false, allowed());
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, [UNCHECKED_RULE]);
}

/// The guard runs git outside every sandbox, so only the `git` the snapshot
/// pins by an absolute path: never one found through the hook's `PATH`,
/// whose relative entries name directories of the repository pushed from.
#[test]
fn a_push_asks_when_the_snapshot_pins_no_absolute_git() {
    let pushes = vec![Push {
        argv: vec!["git".into(), "push".into()],
        dirs: vec![Some("/code/app".into())],
    }];
    let relative: Snapshot = serde_json::from_value(serde_json::json!({
        "version": 1,
        "captured_at_ms": 0,
        "path": ["."],
        "programs": { "git": "./git" },
    }))
    .unwrap();
    let d = super::check(
        &pushes,
        &relative,
        &KnownSecrets::default(),
        false,
        allowed(),
    );
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, [UNCHECKED_RULE]);
}

#[test]
fn a_deny_is_kept_without_reading_the_repository() {
    let denied = Decision::single(Verdict::Deny, "x", "no");
    let unknown = vec![Push {
        argv: vec!["git".into(), "push".into()],
        dirs: vec![None],
    }];
    assert_eq!(
        check(&unknown, &KnownSecrets::default(), true, denied.clone()),
        denied
    );
}
