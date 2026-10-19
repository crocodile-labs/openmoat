//! The push check (docs/POLICY.md §4.2) through the real binary: a git
//! repository with a bare `origin`, both inside the isolated home, and the
//! verdict Claude Code receives for `git push` in it.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;

use crate::common::{Sandbox, bash_payload, output, verdict_and_reason};
use crate::taint::{call, decide};

/// A fake GitHub token of the right shape, built at run time so this source
/// holds no token-shaped text.
pub(crate) fn fake_token() -> String {
    format!("ghp_{}", "Fake0Token".repeat(4))
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `~/repo` on `main`, one commit pushed to `~/origin.git` and tracked.
pub(crate) fn repo(sb: &Sandbox) -> PathBuf {
    let work = sb.home.join("repo");
    let origin = sb.home.join("origin.git");
    let init = ["init", "-q", "--template=", "-b", "main"];
    git(
        &sb.home,
        &[&init[..], &["--bare", origin.to_str().unwrap()]].concat(),
    );
    git(&sb.home, &[&init[..], &[work.to_str().unwrap()]].concat());
    git(
        &work,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    commit(&work, "README.md", "hello\n", "first");
    git(&work, &["push", "-q", "-u", "origin", "main"]);
    work
}

pub(crate) fn commit(work: &Path, file: &str, text: &str, message: &str) {
    let path = work.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    git(work, &["add", "-A"]);
    git(work, &["commit", "-q", "-m", message]);
}

/// The verdict and reason for `command` in `dir`, in session `s1`.
fn push(sb: &Sandbox, dir: &Path, command: &str) -> (String, String) {
    sb.guard_bash("s1", dir, command)
}

/// What the policy alone decides for `git push`: where there is no repository,
/// the push check has nothing to look at.
fn unchecked_decision(sb: &Sandbox) -> String {
    let empty = sb.home.join("not-a-repo");
    std::fs::create_dir_all(&empty).unwrap();
    push(sb, &empty, "git push").0
}

#[test]
fn a_token_in_the_newest_commit_denies_the_push() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    commit(
        &work,
        "conf/app.env",
        &format!("T={}\n", fake_token()),
        "config",
    );
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("push-secret"), "{reason}");
    assert!(reason.contains("conf/app.env"), "{reason}");
    assert!(!reason.contains(&fake_token()), "{reason}");
    // the same push spelled another way
    let (verdict, _) = push(&sb, &sb.home, "cd repo && git -C . push origin main");
    assert_eq!(verdict, "deny");
}

#[test]
fn a_token_in_an_older_commit_of_the_push_denies_it() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    commit(&work, "k.txt", &format!("{}\n", fake_token()), "add");
    commit(&work, "k.txt", "gone\n", "remove");
    commit(&work, "src.txt", "x\n", "later");
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("push-secret"), "{reason}");
}

#[test]
fn a_tainted_session_pushing_a_workflow_change_asks() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    commit(&work, ".github/workflows/ci.yml", "on: push\n", "ci");
    // a clean session: the policy decides, the push check stays quiet
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, unchecked_decision(&sb), "{reason}");
    assert!(!reason.contains("push-"), "{reason}");

    let fetch = json!({"url": "https://crates.io/crates/serde", "prompt": "summarise"});
    let (verdict, _) = decide(&sb, "claude-code", &call("s1", &work, "WebFetch", &fetch));
    assert_eq!(verdict, "allow");
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("push-runs-later"), "{reason}");
    assert!(reason.contains(".github/workflows/ci.yml"), "{reason}");
}

#[test]
fn a_normal_push_keeps_its_verdict() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    commit(&work, "src/lib.rs", "pub fn f() {}\n", "code");
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, unchecked_decision(&sb), "{reason}");
    assert!(!reason.contains("push-"), "{reason}");
}

#[test]
fn without_an_upstream_the_default_branch_is_the_base() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    // a token already on origin's main is not this push's
    commit(&work, "old.txt", &format!("{}\n", fake_token()), "old");
    git(&work, &["push", "-q"]);
    git(&work, &["checkout", "-q", "-b", "feature"]);
    commit(&work, "f.txt", "f\n", "feature");
    let (verdict, reason) = push(&sb, &work, "git push origin feature");
    assert!(!reason.contains("push-"), "{verdict} {reason}");
    commit(&work, "g.txt", &format!("{}\n", fake_token()), "leak");
    let (verdict, reason) = push(&sb, &work, "git push -u origin feature");
    assert_eq!(verdict, "deny", "{reason}");
    assert!(reason.contains("push-secret"), "{reason}");
}

#[test]
fn a_push_not_checked_in_time_or_too_large_asks() {
    let sb = Sandbox::installed(&[".claude"]);
    let work = repo(&sb);
    commit(&work, "src/lib.rs", "pub fn f() {}\n", "code");
    // Debug builds read the check's time budget from the environment.
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", "claude-code"])
        .env("MOAT_TEST_PUSH_BUDGET_MS", "0");
    let out = output(&mut cmd, Some(&bash_payload("s1", &work, "git push")));
    let (verdict, reason) = verdict_and_reason(&out);
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("push-unchecked"), "{reason}");
    assert!(reason.contains("within 0 ms"), "{reason}");

    let line = "abcdefghij".repeat(10) + "\n";
    commit(&work, "big.txt", &line.repeat(90_000), "big");
    let (verdict, reason) = push(&sb, &work, "git push");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("push-unchecked"), "{reason}");
    assert!(reason.contains("more than 8 MiB"), "{reason}");
}
