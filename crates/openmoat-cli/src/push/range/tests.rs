use std::time::{Duration, Instant};

use super::{Spec, revisions, spec};
use crate::push::git::{Git, Unchecked};
use crate::push::testrepo::{Repo, git_program};

fn argv(cmd: &str) -> Vec<String> {
    cmd.split(' ').map(str::to_owned).collect()
}

fn git_in(dir: &std::path::Path) -> Git {
    let budget = Duration::from_secs(10);
    Git::new(git_program(), dir, Instant::now() + budget, budget)
}

/// The subjects of the commits `cmd` would publish from `repo`, newest first.
fn published(repo: &Repo, cmd: &str) -> Option<Vec<String>> {
    let revs = revisions(&git_in(&repo.work), &spec(&argv(cmd))).unwrap()?;
    let mut args = vec!["log".to_owned(), "--format=%s".to_owned()];
    args.extend(revs);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Some(repo.git(&args).lines().map(str::to_owned).collect())
}

#[test]
fn a_push_names_its_remote_and_sources() {
    let s = |cmd: &str| spec(&argv(cmd));
    assert_eq!(s("git push"), Spec::default());
    assert_eq!(
        s("git push -u --force-with-lease origin HEAD +a:b c:refs/heads/c"),
        Spec {
            remote: Some("origin".into()),
            sources: vec!["HEAD".into(), "a".into(), "c".into()],
            ..Spec::default()
        }
    );
    assert_eq!(
        s("git push -o ci.skip --repo up"),
        Spec {
            remote: Some("up".into()),
            ..Spec::default()
        }
    );
    let all = s("git push --mirror backup");
    assert!(all.branches && all.tags && all.sources.is_empty());
    assert!(s("git push origin 'refs/heads/*:refs/heads/*'").branches);
    assert!(s("git push --delete origin x").deletes);
    assert_eq!(s("gh pr create --fill"), Spec::default());
}

#[test]
fn the_current_branch_is_checked_against_its_upstream() {
    let repo = Repo::new();
    assert_eq!(published(&repo, "git push"), Some(vec![]));
    repo.commit("a.txt", "a\n", "second");
    repo.commit("b.txt", "b\n", "third");
    assert_eq!(
        published(&repo, "git push"),
        Some(vec!["third".to_owned(), "second".to_owned()])
    );
    assert_eq!(
        published(&repo, "gh pr create"),
        Some(vec!["third".to_owned(), "second".to_owned()])
    );
}

#[test]
fn without_an_upstream_the_remotes_default_branch_is_the_base() {
    let repo = Repo::new();
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.commit("f.txt", "f\n", "feature work");
    // origin/HEAD is not set: every branch git knows of on origin
    assert_eq!(
        published(&repo, "git push origin feature"),
        Some(vec!["feature work".to_owned()])
    );
    assert_eq!(
        published(&repo, "git push"),
        Some(vec!["feature work".to_owned()])
    );
    repo.git(&["remote", "set-head", "origin", "main"]);
    let revs = revisions(&git_in(&repo.work), &spec(&argv("git push origin feature")))
        .unwrap()
        .unwrap();
    let main = repo.git(&["rev-parse", "origin/main"]);
    assert_eq!(revs.last().map(String::as_str), Some(main.trim()));
    assert_eq!(
        published(&repo, "git push origin HEAD:refs/heads/other"),
        Some(vec!["feature work".to_owned()])
    );
}

#[test]
fn a_remote_git_does_not_know_has_nothing() {
    let repo = Repo::new();
    repo.git(&["remote", "remove", "origin"]);
    let url = repo.origin.to_str().unwrap().to_owned();
    assert_eq!(
        published(&repo, &format!("git push {url} main")),
        Some(vec!["first".to_owned()])
    );
}

#[test]
fn nothing_is_checked_where_nothing_can_be_pushed() {
    let dir = tempfile::tempdir().unwrap();
    // not a repository
    let none = revisions(&git_in(dir.path()), &Spec::default()).unwrap();
    assert_eq!(none, None);
    // nothing committed yet
    crate::push::testrepo::git(dir.path(), &["init", "-q", "--template="]);
    assert_eq!(
        revisions(&git_in(dir.path()), &Spec::default()).unwrap(),
        None
    );
    let repo = Repo::new();
    assert_eq!(published(&repo, "git push origin --delete main"), None);
}

#[test]
fn a_source_that_names_no_commit_is_not_checked() {
    let repo = Repo::new();
    let err = revisions(&git_in(&repo.work), &spec(&argv("git push origin nope"))).unwrap_err();
    assert!(err.0.contains("`nope`"), "{err:?}");
}

#[test]
fn git_stops_at_the_deadline() {
    let repo = Repo::new();
    let late = Git::new(
        git_program(),
        &repo.work,
        Instant::now(),
        Duration::from_millis(0),
    );
    let err = revisions(&late, &Spec::default()).unwrap_err();
    assert_eq!(err, Unchecked("git did not answer within 0 ms".to_owned()));
}
