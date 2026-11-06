//! `openmoat policy check-diff` (ADR-050): a change checked before it is
//! merged, from a diff on stdin and from two git revisions. A pull request is
//! attacker-controlled input: it must not loosen the check by editing the
//! policy in the same change.

use std::path::Path;
use std::process::Command;

use crate::common::{DENY, OK, REVIEW, Sandbox, USAGE, json, output, stdout, text};

fn workflow_edit() -> String {
    "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n\
     index 1111111..2222222 100644\n--- a/.github/workflows/ci.yml\n\
     +++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-on: push\n+on: pull_request_target\n"
        .to_owned()
}

#[test]
fn a_diff_on_stdin_reports_each_level_with_its_exit_code() {
    let sb = Sandbox::bare(&[]);
    let check = |diff: &str, format: &str| {
        sb.moat_stdin(&["policy", "check-diff", "--format", format], diff)
    };
    let out = check(&workflow_edit(), "text");
    assert_eq!(out.status.code(), Some(REVIEW), "{}", text(&out));
    assert!(
        stdout(&out).starts_with("review  .github/workflows/ci.yml"),
        "{}",
        text(&out)
    );

    let settings = "--- a/.claude/settings.json\n+++ b/.claude/settings.json\n@@ -1 +1 @@\n-{}\n+{\"hooks\": {}}\n";
    let out = check(settings, "json");
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    let report = json(&out);
    assert_eq!(report["result"], "deny");
    assert_eq!(report["findings"][0]["path"], ".claude/settings.json");
    assert_eq!(report["findings"][0]["rules"][0], "kernel-self");

    let out = check(&workflow_edit(), "github");
    assert!(
        stdout(&out).starts_with("::warning file=.github/workflows/ci.yml,title=OpenMoat review"),
        "{}",
        text(&out)
    );

    let harmless = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-a\n+b\n";
    let out = check(harmless, "text");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stdout(&out).starts_with("clean: 1 changed files"),
        "{}",
        text(&out)
    );

    // not a diff: an error, never a clean result
    let out = check("this is not a diff\n", "text");
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
}

/// The content checks (ADR-055) on fixture diffs: each finding on its added
/// line, in every format, and benign daily changes left as before.
#[test]
fn content_checks_report_the_added_line_in_every_format() {
    let sb = Sandbox::bare(&[]);
    let check = |diff: &str, format: &str| {
        sb.moat_stdin(&["policy", "check-diff", "--format", format], diff)
    };
    let pwn = include_str!("../../../../tests/fixtures/check-diff/attack/pwn-request.diff");
    let out = check(pwn, "json");
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    let report = json(&out);
    let findings = report["findings"].as_array().unwrap();
    let pr_target = findings
        .iter()
        .find(|f| f["rules"][0] == "diff-ci-pr-target")
        .unwrap_or_else(|| panic!("{report:#}"));
    assert_eq!(pr_target["level"], "deny");
    assert_eq!(pr_target["line"], 11, "{report:#}");

    let out = check(pwn, "github");
    assert!(
        stdout(&out).contains(
            "::error file=.github/workflows/preview.yml,line=11,title=OpenMoat deny%3A diff-ci-pr-target::"
        ),
        "{}",
        text(&out)
    );
    let out = check(pwn, "text");
    assert!(
        stdout(&out).contains("deny    .github/workflows/preview.yml:11 [diff-ci-pr-target]"),
        "{}",
        text(&out)
    );

    let endpoint = include_str!("../../../../tests/fixtures/check-diff/attack/new-endpoint.diff");
    let out = check(endpoint, "json");
    assert_eq!(out.status.code(), Some(REVIEW), "{}", text(&out));
    let report = json(&out);
    let hosts: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rules"][0] == "diff-new-host")
        .collect();
    assert_eq!(hosts.len(), 1, "{report:#}");
    assert_eq!(hosts[0]["path"], "src/telemetry.ts");

    let benign = include_str!("../../../../tests/fixtures/check-diff/benign/docs-and-code.diff");
    let out = check(benign, "text");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let key = include_str!("../../../../tests/fixtures/check-diff/benign/test-fixture-key.diff");
    assert_eq!(check(key, "text").status.code(), Some(REVIEW));
}

/// A policy given with `--policy` sets the content checks' levels.
#[test]
fn the_policy_file_sets_the_content_checks_levels() {
    let sb = Sandbox::bare(&[]);
    let policy = sb.home.join("team.yaml");
    std::fs::write(
        &policy,
        format!(
            "{}\ncheck_diff:\n  levels:\n    diff-new-host: off\n",
            openmoat_core::DEFAULT_POLICY
        ),
    )
    .unwrap();
    let endpoint = include_str!("../../../../tests/fixtures/check-diff/attack/new-endpoint.diff");
    let policy = policy.to_str().unwrap();
    let out = sb.moat_stdin(&["policy", "check-diff", "--policy", policy], endpoint);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
}

/// `cmd` working in the repository `dir`, whose git directory is beside it
/// rather than `dir/.git`: some sandboxes the suite runs in (macOS 12's
/// Seatbelt under an agent) refuse to create a `.git` directory.
fn in_repo<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.current_dir(dir)
        .env("GIT_DIR", dir.with_extension("gitdir"))
        .env("GIT_WORK_TREE", dir)
}

/// `git` in `dir` with a fixed identity, for the test's own commits.
fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    let status = in_repo(&mut cmd, dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn write(dir: &Path, file: &str, text: &str) {
    let path = dir.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const FROZEN: &str = "version: 1\ndeny:\n  - id: frozen\n    reason: release notes are frozen\n    \
     fs.write: ['${project}/docs/release/**']\n";

/// A repository whose `main` has `policy_file` holding [`FROZEN`], and whose
/// branch `change` empties that file and edits what it protected. Returns the
/// report of checking `change` against `main` with `args`.
fn loosening_change(policy_file: &str, args: &[&str]) -> serde_json::Value {
    let sb = Sandbox::bare(&[]);
    let repo = sb.home.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "--template="]);
    write(&repo, policy_file, FROZEN);
    write(&repo, "docs/release/notes.md", "v1\n");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    git(&repo, &["checkout", "-q", "-b", "change"]);
    write(&repo, policy_file, "version: 1\n");
    write(&repo, "docs/release/notes.md", "v2\n");
    git(&repo, &["commit", "-q", "-am", "change"]);

    let mut cmd = sb.command();
    in_repo(&mut cmd, &repo)
        .args(["policy", "check-diff", "--base", "main", "--head", "change"])
        .args(["--format", "json"])
        .args(args);
    let out = output(&mut cmd, None);
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    let report = json(&out);
    let findings = report["findings"].as_array().unwrap();
    let find = |path: &str| {
        findings
            .iter()
            .find(|f| f["path"] == path)
            .unwrap_or_else(|| panic!("{path}: {report:#}"))
            .clone()
    };
    assert!(
        find("docs/release/notes.md")["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().ends_with("frozen")),
        "{report:#}"
    );
    let changed = find(policy_file);
    assert!(
        changed["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "diff-policy"),
        "{report:#}"
    );

    // a revision that git would read as an option is refused, a usage error
    let mut cmd = sb.command();
    in_repo(&mut cmd, &repo).args(["policy", "check-diff", "--base=--output=x"]);
    assert_eq!(output(&mut cmd, None).status.code(), Some(USAGE));
    report
}

#[test]
fn a_change_cannot_loosen_the_policy_file_it_is_checked_against() {
    let report = loosening_change("ci/team-policy.yaml", &["--policy", "ci/team-policy.yaml"]);
    assert!(
        report["policy"]
            .as_str()
            .unwrap()
            .starts_with("ci/team-policy.yaml at "),
        "{report:#}"
    );
}

/// Creates a `.moat` directory, which macOS 12's Seatbelt under an agent refuses.
#[test]
fn a_change_cannot_loosen_the_repository_policy() {
    let report = loosening_change(".moat/policy.yaml", &[]);
    assert!(
        report["repository_policy"]
            .as_str()
            .unwrap()
            .starts_with(".moat/policy.yaml at "),
        "{report:#}"
    );
}
