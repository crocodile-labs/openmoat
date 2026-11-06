//! Provenance notes in `openmoat policy check-diff` (ADR-056): a note on a
//! commit of the change is shown beside the report and never changes its exit
//! code; `--provenance off`, no notes, or a diff on stdin show nothing.

use std::path::Path;
use std::process::Command;

use crate::common::{OK, Sandbox, json, output, text};

/// `cmd` in the repository `dir`, whose git directory is beside it (some
/// sandboxes refuse to create a `.git` directory; see `check_diff.rs`).
fn in_repo<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.current_dir(dir)
        .env("GIT_DIR", dir.with_extension("gitdir"))
        .env("GIT_WORK_TREE", dir)
}

/// `git` in `dir` with a fixed identity; its standard output.
fn git(dir: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    let out = in_repo(&mut cmd, dir)
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
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A note as `openmoat provenance --write-notes` writes it: one session
/// that wrote `src/lib.rs` after reading a web page.
fn note(commit: &str) -> String {
    serde_json::json!({
        "format": "openmoat-provenance-v1",
        "commit": commit,
        "head": { "event": 9, "hash": "ab" },
        "events": [{ "event": 7, "hash": "cd" }],
        "digest": "ef",
        "files": [{
            "path": "src/lib.rs",
            "host": "claude-code",
            "session": "3c9e1a7f02d4aa",
            "event": 7,
            "ts_ms": 1,
            "evidence": "lines",
            "lines": [{ "start": 1, "end": 2 }],
            "untrusted": { "kind": "web", "source": "fetch docs.example.com" }
        }]
    })
    .to_string()
}

fn check(sb: &Sandbox, repo: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = sb.command();
    in_repo(&mut cmd, repo)
        .args(["policy", "check-diff", "--base", "main", "--head", "change"])
        .args(args);
    output(&mut cmd, None)
}

#[test]
fn check_diff_shows_provenance_notes_without_changing_its_verdict() {
    let sb = Sandbox::bare(&[]);
    let repo = sb.home.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q", "--template="]);
    std::fs::write(repo.join("README.md"), "x\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    git(&repo, &["checkout", "-q", "-b", "change"]);
    std::fs::write(repo.join("src/lib.rs"), "a\nb\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "change"]);

    // no notes yet: the report is as before
    let out = check(&sb, &repo, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(json(&out).get("provenance").is_none(), "{}", text(&out));

    let head = git(&repo, &["rev-parse", "HEAD"]);
    let body = note(&head);
    git(
        &repo,
        &[
            "notes",
            "--ref",
            "refs/notes/openmoat",
            "add",
            "-m",
            &body,
            &head,
        ],
    );

    let out = check(&sb, &repo, &["--format", "json"]);
    assert_eq!(
        out.status.code(),
        Some(OK),
        "never a verdict: {}",
        text(&out)
    );
    let report = json(&out);
    assert_eq!(report["result"], "clean", "{report:#}");
    let section = &report["provenance"];
    assert_eq!(section["level"], "review", "{report:#}");
    assert_eq!(section["noted_commits"], 1);
    assert_eq!(section["sessions"][0]["lines"], 2);
    assert_eq!(section["sessions"][0]["untrusted"]["kind"], "web");

    let out = check(&sb, &repo, &["--format", "github", "--provenance", "info"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = text(&out);
    assert!(
        shown.contains(
            "::notice title=OpenMoat provenance::1 file / 2 lines written by claude-code \
             (session 3c9e1a7f02d4, after reading web content (fetch docs.example.com))"
        ),
        "{shown}"
    );
    assert!(
        shown.contains("a commit without one proves nothing"),
        "{shown}"
    );

    let out = check(&sb, &repo, &["--format", "text", "--provenance", "off"]);
    assert!(!text(&out).contains("provenance"), "{}", text(&out));

    // a note that is not one is reported, not an error
    git(
        &repo,
        &[
            "notes",
            "--ref",
            "refs/notes/openmoat",
            "add",
            "-f",
            "-m",
            "hello",
            &head,
        ],
    );
    let out = check(&sb, &repo, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let report = json(&out);
    assert_eq!(
        report["provenance"]["unreadable"][0],
        head.as_str(),
        "{report:#}"
    );
}
