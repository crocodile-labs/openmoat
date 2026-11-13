//! What the policy denies inside the project holds in every Linux tier
//! (ADR-090): without a network namespace the project is granted entry by
//! entry, and in the Isolated tier a folder of an agent's configuration
//! missing at the start is a read-only folder, so a hook written into it after
//! the start is refused. Each case asserts the effect on disk, not the verdict.

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use super::confined::{isolated, ran};
use super::{installed_with_secret, run_sh_with};
use crate::common::{stderr, stdout, text};

/// Generated for the test; nothing real.
const SECRET: &str = "TOKEN=fake-project-secret-7c1e";

/// Whether `script`'s line `name=<status>` says the step succeeded.
fn succeeded(out: &Output, name: &str) -> bool {
    stdout(out).contains(&format!("{name}=0\n"))
}

fn bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// A test build without the network namespace: the Lightweight tier as on a
/// machine without bubblewrap. Commands cannot read the project's `.env`,
/// write its `.git` or `.moat`, create `.envrc` or a new git hook, or move an
/// entry at its top aside; inside a folder that exists they work as before.
/// Creating a new entry at the top is refused too: the cost ADR-090 names.
#[test]
fn without_a_namespace_the_project_is_granted_entry_by_entry() {
    let (sb, project) = installed_with_secret();
    for dir in [".git/hooks", ".moat", "src", "sub"] {
        std::fs::create_dir_all(project.join(dir)).unwrap();
    }
    std::fs::write(project.join(".env"), SECRET).unwrap();
    std::fs::write(project.join("sub/.env"), "deeper").unwrap();
    std::fs::write(project.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(project.join(".moat/notes.txt"), "kept").unwrap();
    std::fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();
    let before = [".env", ".git/hooks/pre-commit", ".moat/notes.txt"]
        .map(|file| (file, bytes(&project.join(file))));
    let script = "cat .env; echo \"env=$?\"
         echo PLANTED >> .git/hooks/pre-commit; echo \"hook=$?\"
         echo PLANTED > .git/hooks/post-checkout; echo \"newhook=$?\"
         echo PLANTED > .moat/policy.yaml; echo \"policy=$?\"
         echo PLANTED > .envrc; echo \"envrc=$?\"
         mv .git git-aside; echo \"move=$?\"
         echo x > top.txt; echo \"top=$?\"
         echo '// ok' >> src/main.rs; echo \"inside=$?\"
         ls -a > /dev/null; echo \"list=$?\"";
    let out = run_sh_with(&sb, &project, script, &[("MOAT_TEST_NO_NETNS", "1")]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stderr(&out).contains("restricted by port only"), "{shown}");
    assert!(stderr(&out).contains("granted entry by entry"), "{shown}");
    // The deeper `.env` lies in a folder granted whole, and is named.
    assert!(stderr(&out).contains("/sub/.env"), "{shown}");
    for refused in ["env", "hook", "newhook", "policy", "envrc", "move", "top"] {
        assert!(!succeeded(&out, refused), "{refused}: {shown}");
    }
    for allowed in ["inside", "list"] {
        assert!(succeeded(&out, allowed), "{allowed}: {shown}");
    }
    assert!(shown.contains("Permission denied"), "EACCES: {shown}");
    assert!(!shown.contains(SECRET), "{shown}");
    for (file, was) in before {
        assert!(bytes(&project.join(file)) == was, "{file} changed");
    }
    for absent in [
        ".git/hooks/post-checkout",
        ".moat/policy.yaml",
        ".envrc",
        "top.txt",
        "git-aside",
    ] {
        assert!(!project.join(absent).exists(), "{absent}: {shown}");
    }
    assert!(bytes(&project.join("src/main.rs")).ends_with(b"// ok\n"));
}

/// The Isolated tier: `.env` written by the person after the start stays
/// unreadable to commands (its placeholder is covered), and a hook written
/// after the start into `.git/hooks`, a `.claude/hooks` or `.github/hooks`
/// that did not exist is refused; the placeholder folders are gone afterwards.
#[test]
fn files_created_after_the_start_stay_covered_in_the_isolated_tier() {
    let (sb, project) = installed_with_secret();
    for dir in [".git/hooks", ".claude", ".github"] {
        std::fs::create_dir_all(project.join(dir)).unwrap();
    }
    let script = "touch .late-started
         i=0; while [ ! -e .late-go ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done
         cat .env; echo \"env=$?\"
         echo PLANTED > .git/hooks/post-checkout; echo \"githook=$?\"
         echo PLANTED > .claude/hooks/run.sh; echo \"claude=$?\"
         echo PLANTED > .github/hooks/hooks.json; echo \"github=$?\"
         echo finished";
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let mut child = sb
        .command()
        .current_dir(&project)
        .env("TMPDIR", &tmp)
        .args(["run", "--isolate", "--", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !project.join(".late-started").exists()
        && child.try_wait().unwrap().is_none()
        && started.elapsed() < Duration::from_secs(60)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    // Written as the person, outside the sandbox, after the agent started.
    std::fs::write(project.join(".env"), SECRET).unwrap();
    std::fs::write(project.join(".late-go"), "").unwrap();
    let out = child.wait_with_output().unwrap();
    if !ran(&out) || !isolated(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains("finished"), "{shown}");
    for refused in ["env", "githook", "claude", "github"] {
        assert!(!succeeded(&out, refused), "{refused}: {shown}");
    }
    assert!(!shown.contains(SECRET), "{shown}");
    for absent in [
        ".git/hooks/post-checkout",
        ".claude/hooks/run.sh",
        ".github/hooks/hooks.json",
    ] {
        assert!(!project.join(absent).exists(), "{absent}: {shown}");
    }
    // The empty folders made for the session are removed; the person's
    // `.env` is theirs and stays.
    for gone in [".claude/hooks", ".github/hooks"] {
        assert!(!project.join(gone).exists(), "{gone}: {shown}");
    }
    assert_eq!(bytes(&project.join(".env")), SECRET.as_bytes());
}

/// The default read root `~/go` is a link to the folder holding the project:
/// Landlock resolves a rule's path, so that root reached the project whole,
/// `.env` included. It is granted around the project from where it resolves,
/// and the project's `.env` stays unreadable (a test build without the
/// network namespace, as on a machine without bubblewrap).
#[test]
fn a_read_root_linked_above_the_project_does_not_grant_it_whole() {
    let (sb, _) = installed_with_secret();
    let parent = sb.home.join("work/src");
    let project = parent.join("app");
    for dir in [".git/hooks", "src"] {
        std::fs::create_dir_all(project.join(dir)).unwrap();
    }
    std::fs::create_dir_all(parent.join("other")).unwrap();
    std::fs::write(parent.join("other/notes.txt"), "beside").unwrap();
    std::fs::write(project.join(".env"), SECRET).unwrap();
    std::os::unix::fs::symlink(sb.home.join("work"), sb.home.join("go")).unwrap();
    let script = "cat .env; echo \"env=$?\"
         cat \"$HOME/go/src/app/.env\"; echo \"linked=$?\"
         cat \"$HOME/go/src/other/notes.txt\"; echo \"beside=$?\"";
    let out = run_sh_with(&sb, &project, script, &[("MOAT_TEST_NO_NETNS", "1")]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stderr(&out).contains("granted entry by entry"), "{shown}");
    for refused in ["env", "linked"] {
        assert!(!succeeded(&out, refused), "{refused}: {shown}");
    }
    // The read root still reads what lies beside the project.
    assert!(succeeded(&out, "beside"), "{shown}");
    assert!(!shown.contains(SECRET), "{shown}");
    assert_eq!(bytes(&project.join(".env")), SECRET.as_bytes());
}

/// `sb` with `sandbox.project_top: writable` in the person's own policy,
/// re-pinned as a person would.
fn open_top(sb: &crate::common::Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let policy = std::fs::read_to_string(&path).unwrap();
    let edited = policy.replacen("\nsandbox:\n", "\nsandbox:\n  project_top: writable\n", 1);
    assert_ne!(
        policy, edited,
        "the default policy has a `sandbox:` section"
    );
    std::fs::write(&path, edited).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

/// The person's own `sandbox.project_top: writable` gives back, without a
/// network namespace, the whole-project grant: a new file at the top can be
/// made, and `.env` there is open, which the start notice says and the audit
/// log records (`run-project-top-open`); `doctor` warns. A policy that requires
/// the full boundary still refuses to start without the namespace.
#[test]
fn the_persons_policy_can_open_the_project_top_on_record() {
    let (sb, project) = installed_with_secret();
    open_top(&sb);
    std::fs::write(project.join(".env"), SECRET).unwrap();
    let script = "echo x > top.txt; echo \"top=$?\"";
    let out = run_sh_with(&sb, &project, script, &[("MOAT_TEST_NO_NETNS", "1")]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(succeeded(&out, "top"), "{shown}");
    assert!(project.join("top.txt").exists(), "{shown}");
    for said in [
        "sandbox.project_top: writable",
        "`.git/hooks`",
        "run-project-top-open",
    ] {
        assert!(stderr(&out).contains(said), "{said}: {shown}");
    }
    let rows = super::default_tier::tier_rows(&sb);
    assert!(rows.iter().any(|r| r == "run-project-top-open"), "{rows:?}");
    // `doctor` warns where `openmoat run` would have no namespace.
    let doctor = sb
        .command()
        .current_dir(&project)
        .env("MOAT_TEST_NO_NETNS", "1")
        .arg("doctor")
        .output()
        .unwrap();
    assert!(
        text(&doctor).contains("`sandbox.project_top: writable`"),
        "{}",
        text(&doctor)
    );
    super::strict::require(&sb, super::strict::STRICT);
    let refused = run_sh_with(
        &sb,
        &project,
        "echo started",
        &[("MOAT_TEST_NO_NETNS", "1")],
    );
    assert_eq!(
        refused.status.code(),
        Some(crate::common::USAGE),
        "{}",
        text(&refused)
    );
    assert!(!stdout(&refused).contains("started"), "{}", text(&refused));
    assert!(
        stderr(&refused).contains("full-boundary"),
        "{}",
        text(&refused)
    );
}
