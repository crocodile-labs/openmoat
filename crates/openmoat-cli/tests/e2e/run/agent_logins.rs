//! ADR-054: `openmoat run` keeps the login of the agent it starts readable and
//! denies every other agent's, inside a `--write` path too; for a program that
//! is no agent OpenMoat knows, the logins inside its `--write` paths stay.

use std::path::Path;
use std::process::Output;

use super::confined::ran;
use super::installed_with_secret;
use crate::common::{Sandbox, output, stderr, stdout, text};

/// Reads Claude Code's and Codex's login files and says which opened.
const SCRIPT: &str = "cat \"$HOME/.claude/.credentials.json\"; echo \"claude=$?\"
                      cat \"$HOME/.codex/auth.json\"; echo \"codex=$?\"";

/// `openmoat run --write ~/.claude --write ~/.codex -- <program> -c SCRIPT`,
/// with fake logins for both agents in place.
fn run_as(sb: &Sandbox, project: &Path, program: &Path) -> Output {
    for (dir, file, value) in [
        (".claude", ".credentials.json", "FAKE-CLAUDE-LOGIN"),
        (".codex", "auth.json", "FAKE-CODEX-LOGIN"),
    ] {
        std::fs::create_dir_all(sb.home.join(dir)).unwrap();
        std::fs::write(sb.home.join(dir).join(file), value).unwrap();
    }
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let (claude, codex) = (sb.home.join(".claude"), sb.home.join(".codex"));
    output(
        sb.command()
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .arg("run")
            .arg("--write")
            .arg(&claude)
            .arg("--write")
            .arg(&codex)
            .arg("--")
            .arg(program)
            .args(["-c", SCRIPT]),
        None,
    )
}

/// False, saying so, where Linux has no network namespace for `moat run`:
/// there it refuses `--write` paths outside the project. CI has one.
fn namespaced(out: &Output) -> bool {
    let refused = stderr(out).contains("Install bubblewrap");
    super::check_netns(refused, &text(out));
    if refused {
        eprintln!("skipped: bubblewrap cannot make a network namespace here");
    }
    !refused
}

#[test]
fn the_running_agent_keeps_its_login_and_cannot_read_another_agents() {
    let (sb, project) = installed_with_secret();
    // A program named as Claude Code is: `openmoat run` finds the agent by the
    // name it is started as, and the sandbox runs the file the link names.
    let bin = sb.home.with_file_name("agent-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let claude = bin.join("claude");
    std::os::unix::fs::symlink("/bin/sh", &claude).unwrap();
    let out = run_as(&sb, &project, &claude);
    if !ran(&out) || !namespaced(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains("claude=0\n"), "{shown}");
    assert!(shown.contains("FAKE-CLAUDE-LOGIN"), "{shown}");
    assert!(!stdout(&out).contains("codex=0\n"), "{shown}");
    assert!(!shown.contains("FAKE-CODEX-LOGIN"), "{shown}");
}

#[test]
fn another_program_keeps_the_logins_in_its_write_paths() {
    let (sb, project) = installed_with_secret();
    let out = run_as(&sb, &project, Path::new("/bin/sh"));
    if !ran(&out) || !namespaced(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains("claude=0\n"), "{shown}");
    assert!(stdout(&out).contains("codex=0\n"), "{shown}");
}
