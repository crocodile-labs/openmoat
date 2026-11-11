//! Workspace snapshots and `openmoat restore` (ADR-085), in a throwaway home:
//! the store under the state directory, what a snapshot leaves out, a
//! restore that shows the change and asks, and a project or person git
//! configuration that must not run.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use crate::common::{OK, Sandbox, output, stderr, text};
use crate::run::installed_with_secret;

/// `openmoat <args>` in `project` as a person at a terminal, answering `stdin`.
fn person(sb: &Sandbox, project: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .env("MOAT_ASSUME_TTY", "1")
            .args(args),
        stdin,
    )
}

fn listed(sb: &Sandbox, project: &Path) -> Vec<Value> {
    let out = person(
        sb,
        project,
        &["snapshot", "--list", "--format", "json"],
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    serde_json::from_slice::<Value>(&out.stdout)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn left_out(snapshot: &Value) -> Vec<(String, String)> {
    snapshot["meta"]["left_out"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["path"].as_str().unwrap().to_owned(),
                o["why"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// Every store folder under the state directory.
fn stores(sb: &Sandbox) -> Vec<PathBuf> {
    let dir = sb.home.join(".moat").join("snapshots");
    std::fs::read_dir(dir)
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default()
}

/// What `git cat-file --batch-all-objects --batch` prints of `store`.
fn every_object(sb: &Sandbox, store: &Path) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("GIT_DIR", store)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write(project: &Path, rel: &str, text: &str) {
    let path = project.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn read(project: &Path, rel: &str) -> String {
    std::fs::read_to_string(project.join(rel)).unwrap()
}

#[test]
fn a_snapshot_leaves_out_secrets_ignored_and_large_files_and_a_restore_puts_files_back() {
    let (sb, project) = installed_with_secret();
    write(&project, "src/main.rs", "fn main() {}\n");
    write(&project, "notes.txt", "mine\n");
    write(&project, ".env", "TOKEN=FAKE-ENV-VALUE\n");
    write(&project, ".gitignore", "target/\n");
    write(&project, "target/out", "built\n");
    write(&project, ".git/info/exclude", "local.txt\n");
    write(&project, "local.txt", "excluded\n");
    write(&project, "big.bin", &"x".repeat(6 << 20));
    std::os::unix::fs::symlink("notes.txt", project.join("link")).unwrap();
    let out = person(&sb, &project, &["snapshot"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("taken by hand"), "{}", text(&out));

    let snapshots = listed(&sb, &project);
    assert_eq!(snapshots.len(), 1, "{snapshots:?}");
    let s = &snapshots[0];
    // .gitignore, link, notes.txt, src/main.rs
    assert_eq!(s["meta"]["files"], 4, "{s}");
    let left = left_out(s);
    assert!(
        left.contains(&(".env".to_owned(), "denied".to_owned())),
        "{left:?}"
    );
    assert!(
        left.contains(&("big.bin".to_owned(), "too-large".to_owned())),
        "{left:?}"
    );
    assert!(
        !left
            .iter()
            .any(|(p, _)| p.starts_with("target") || p == "local.txt")
    );

    // The store is in the state directory, never the project, and holds no secret.
    let store = stores(&sb);
    assert_eq!(store.len(), 1, "{store:?}");
    assert!(!every_object(&sb, &store[0]).contains("FAKE-ENV-VALUE"));
    let mode = std::fs::metadata(&store[0]).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "{mode:o}");

    // The agent's damage.
    write(&project, "src/main.rs", "broken\n");
    std::fs::remove_file(project.join("notes.txt")).unwrap();
    write(&project, "scratch.txt", "agent\n");
    let id = s["id"].as_str().unwrap();

    // A "no" changes nothing.
    let out = person(&sb, &project, &["restore", id], Some("n\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("changed back src/main.rs"), "{shown}");
    assert!(shown.contains("added back   notes.txt"), "{shown}");
    assert!(shown.contains("deleted      scratch.txt"), "{shown}");
    assert!(shown.contains("not restored .env"), "{shown}");
    assert!(shown.contains("nothing changed"), "{shown}");
    assert_eq!(read(&project, "src/main.rs"), "broken\n");

    let out = person(&sb, &project, &["restore", id, "--patch"], Some("y\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("-broken"), "{}", text(&out));
    assert_eq!(read(&project, "src/main.rs"), "fn main() {}\n");
    assert_eq!(read(&project, "notes.txt"), "mine\n");
    assert!(!project.join("scratch.txt").exists());
    // What the snapshot left out is as it was.
    assert_eq!(read(&project, ".env"), "TOKEN=FAKE-ENV-VALUE\n");
    assert_eq!(read(&project, "target/out"), "built\n");
    assert_eq!(
        std::fs::metadata(project.join("big.bin")).unwrap().len(),
        6 << 20
    );

    // The restore can be undone: the undo snapshot holds the agent's files.
    let undo = text(&out)
        .split("undo with `openmoat restore ")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
        .unwrap()
        .to_owned();
    let out = person(&sb, &project, &["restore", &undo], Some("y\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(read(&project, "scratch.txt"), "agent\n");
}

/// The project's `.git/config` and the person's `~/.gitconfig` name programs
/// git would run while it reads the files (a file system monitor, a clean
/// filter the project's `.gitattributes` asks for): none runs.
#[test]
fn no_git_configuration_of_the_project_or_the_person_runs() {
    let (sb, project) = installed_with_secret();
    let marker = sb.home.join("ran");
    let script = sb.home.join("evil.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = format!(
        "[core]\n\tfsmonitor = {0}\n[filter \"evil\"]\n\tclean = {0}\n\tsmudge = {0}\n\trequired = true\n",
        script.display()
    );
    write(&project, ".git/config", &config);
    std::fs::write(sb.home.join(".gitconfig"), &config).unwrap();
    write(&project, ".gitattributes", "* filter=evil\n");
    write(&project, "a.txt", "a\n");
    let out = person(&sb, &project, &["snapshot"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    write(&project, "a.txt", "b\n");
    let id = listed(&sb, &project)[0]["id"].as_str().unwrap().to_owned();
    let out = person(&sb, &project, &["restore", &id], Some("y\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(read(&project, "a.txt"), "a\n");
    assert!(!marker.exists(), "a program the configuration names ran");
    // The project's own repository is as it was.
    assert_eq!(read(&project, ".git/config"), config);
    assert!(!project.join(".git/index").exists());
}

/// An agent's `.gitignore` that ignores everything: the snapshot is still
/// taken, holds nothing, and says so.
#[test]
fn a_gitignore_that_ignores_everything_still_records_a_snapshot() {
    let (sb, project) = installed_with_secret();
    write(&project, ".gitignore", "*\n");
    write(&project, "a.txt", "a\n");
    let out = person(&sb, &project, &["snapshot"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let s = listed(&sb, &project);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0]["meta"]["files"], 0, "{:?}", s[0]);
}

/// Without a person at a terminal, `restore` refuses before it reads anything.
#[test]
fn restore_without_a_terminal_is_refused() {
    let (sb, project) = installed_with_secret();
    let out = output(
        sb.command().current_dir(&project).args(["restore"]),
        Some("y\n"),
    );
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stderr(&out).contains("must be run by a person"),
        "{}",
        text(&out)
    );
}

/// The restore path a link left in the project points out of: nothing is
/// written through it.
#[test]
fn a_restore_does_not_write_through_a_link_to_outside_the_project() {
    let (sb, project) = installed_with_secret();
    write(&project, "src/lib.rs", "lib\n");
    let out = person(&sb, &project, &["snapshot"], None);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let outside = sb.home.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::remove_dir_all(project.join("src")).unwrap();
    std::os::unix::fs::symlink(&outside, project.join("src")).unwrap();
    write(&project, ".gitignore", "src\n");
    let id = listed(&sb, &project)[0]["id"].as_str().unwrap().to_owned();
    let out = person(&sb, &project, &["restore", &id], Some("y\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        text(&out).contains("not changed: src/lib.rs"),
        "{}",
        text(&out)
    );
    assert!(!outside.join("lib.rs").exists());
}

/// `openmoat run` takes a snapshot before the agent starts and after it
/// exits; `openmoat restore` alone goes back to the one before.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn run_takes_snapshots_before_and_after_and_restore_goes_back_to_before() {
    let (sb, project) = installed_with_secret();
    write(&project, "a.txt", "a\n");
    let out = crate::run::run_sh_with(&sb, &project, "rm a.txt; echo agent > b.txt", &[]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stderr(&out).contains("before the agent started"),
        "{}",
        text(&out)
    );
    assert!(
        stderr(&out).contains("after the agent exited"),
        "{}",
        text(&out)
    );
    let reasons: Vec<String> = listed(&sb, &project)
        .iter()
        .map(|s| s["meta"]["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(reasons, ["run-start", "run-exit"]);
    let out = person(&sb, &project, &["restore"], Some("y\n"));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(read(&project, "a.txt"), "a\n");
    assert!(!project.join("b.txt").exists());
    // The audit log records both snapshots and the restore.
    let out = sb.moat(&["show", "--recent", "20"]);
    let shown = text(&out);
    assert!(
        shown.contains("openmoat") && shown.contains("snapshot"),
        "{shown}"
    );
    assert!(shown.contains("restore"), "{shown}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn run_with_no_snapshot_takes_none() {
    let (sb, project) = installed_with_secret();
    write(&project, "a.txt", "a\n");
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .env("TMPDIR", &tmp)
            .args(["run", "--no-snapshot", "--", "/bin/sh", "-c", "true"]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stderr(&out).contains("--no-snapshot"), "{}", text(&out));
    assert_eq!(stores(&sb), Vec::<PathBuf>::new());
}

/// Inside `openmoat run`, the agent's own `openmoat restore` and `openmoat
/// snapshot` are refused by the binary (a run is among their parents), and the
/// sandbox keeps the store out of reach.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn inside_run_the_agent_cannot_restore_snapshot_or_touch_the_store() {
    let (sb, project) = installed_with_secret();
    write(&project, "a.txt", "a\n");
    let moat = env!("CARGO_BIN_EXE_openmoat");
    let store = sb.home.join(".moat").join("snapshots");
    let script = format!(
        "'{moat}' restore </dev/null; echo \"restore=$?\"; \
         '{moat}' snapshot; echo \"snapshot=$?\"; \
         ls '{store}' >/dev/null 2>&1; echo \"ls=$?\"; \
         rm -rf '{store}' 2>/dev/null; echo \"rm=$?\"",
        store = store.display()
    );
    let out = crate::run::run_sh_with(&sb, &project, &script, &[]);
    let shown = text(&out);
    for refused in ["restore=0", "snapshot=0", "ls=0"] {
        assert!(!shown.contains(refused), "{refused}: {shown}");
    }
    // The store the run itself took is still there.
    assert_eq!(stores(&sb).len(), 1, "{shown}");
}
