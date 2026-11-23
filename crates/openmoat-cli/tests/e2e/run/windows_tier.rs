//! Windows (ADR-115): `openmoat run` starts the program under a
//! write-restricted token in a kill-on-close job. The payloads are `cmd.exe`
//! scripts, never an agent, in an isolated home. No test sleeps: the one wait
//! is for the job's processes to be gone, polled with `tasklist`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use super::installed_with_secret;
use crate::common::{FAILED, OK, Sandbox, output, stderr, stdout, text};

/// `openmoat run [flags] -- cmd /d /c <script>` in `project`.
fn run_cmd(sb: &Sandbox, project: &Path, flags: &[&str], script: &str) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .arg("run")
            .args(flags)
            .args(["--", "cmd", "/d", "/c", script]),
        None,
    )
}

/// A directory outside the project and the home, in the system's temp
/// directory, whose access list is the person's alone.
fn outside() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("openmoat-outside-")
        .tempdir()
        .unwrap()
}

/// A write inside the project goes through; the same write outside it is
/// refused by the token, and nothing lands there.
#[test]
fn writes_go_through_in_the_project_and_are_refused_outside_it() {
    let (sb, project) = installed_with_secret();
    let inside = project.join("inside.txt");
    let out = run_cmd(
        &sb,
        &project,
        &[],
        &format!("echo inside>{}", inside.display()),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        std::fs::read_to_string(&inside).is_ok_and(|t| t.contains("inside")),
        "{}",
        text(&out)
    );
    assert!(
        stderr(&out).contains("Windows preview tier"),
        "{}",
        text(&out)
    );

    let away = outside();
    let target = away.path().join("outside.txt");
    let out = run_cmd(
        &sb,
        &project,
        &[],
        &format!("echo outside>{}", target.display()),
    );
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    assert!(
        !target.exists(),
        "the write outside the project went through"
    );
    assert!(stderr(&out).contains("denied"), "{}", text(&out));

    // The project's `.git` is the policy's to hold: a deny entry for the
    // project's SID, set because the folder exists when the run starts.
    let git = project.join(".git");
    std::fs::create_dir_all(&git).unwrap();
    let hook = git.join("planted-hook");
    let out = run_cmd(&sb, &project, &[], &format!("echo x>{}", hook.display()));
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    assert!(!hook.exists(), "the write in .git went through");

    // The person's home, outside the project too.
    let home_file = sb.home.join("planted.txt");
    let out = run_cmd(
        &sb,
        &project,
        &[],
        &format!("echo x>{}", home_file.display()),
    );
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    assert!(!home_file.exists(), "the write in the home went through");
}

/// The token's write check covers a folder's access list too: a command
/// cannot grant `Everyone` a folder outside the project and then write it.
#[test]
fn an_access_list_outside_the_project_cannot_be_widened() {
    let (sb, project) = installed_with_secret();
    let away = outside();
    let script = format!(
        "icacls {} /grant *S-1-1-0:(OI)(CI)M /q",
        away.path().display()
    );
    let out = run_cmd(&sb, &project, &[], &script);
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    let listed = Command::new("icacls").arg(away.path()).output().unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !listed.contains("Everyone") && !listed.contains("S-1-1-0"),
        "the access list was widened: {listed}"
    );
}

/// What the agent started and left running ends with the run: the job
/// kills it, and no process may leave the job.
#[test]
fn the_job_ends_what_the_agent_left_running() {
    let (sb, project) = installed_with_secret();
    let tools = outside();
    let name = format!("openmoat-job-{}.exe", std::process::id());
    let system =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let copy = tools.path().join(&name);
    std::fs::copy(system.join(r"System32\cmd.exe"), &copy).unwrap();
    let started = project.join("started.txt");
    let grandchild = project.join("grandchild.cmd");
    // Started under its own name, so `tasklist` finds it and nothing else;
    // it writes its mark, then waits five minutes.
    std::fs::write(
        &grandchild,
        format!(
            "@echo started>{}\r\n@ping -n 300 127.0.0.1 >NUL\r\n",
            started.display()
        ),
    )
    .unwrap();
    let agent = project.join("agent.cmd");
    std::fs::write(
        &agent,
        format!(
            "@start /b {} /d /c {} >NUL 2>NUL\r\n:wait\r\n@if not exist {} goto wait\r\n@exit /b 0\r\n",
            copy.display(),
            grandchild.display(),
            started.display()
        ),
    )
    .unwrap();
    let out = run_cmd(&sb, &project, &[], &agent.display().to_string());
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        started.exists(),
        "the grandchild never started: {}",
        text(&out)
    );
    let running = || {
        let list = Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {name}"), "/NH"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&list.stdout).contains(&name)
    };
    // Ending a job's processes is asynchronous; each `tasklist` takes a
    // moment, so a few tries are the wait.
    let gone = (0..50).any(|_| !running());
    assert!(gone, "the agent's grandchild outlived the run");
}

/// `--print-boundary` names the Windows tier honestly: the token and the job
/// planned, the network held by the proxy variables only, and a score that
/// counts the network filter and read denial it does not have.
#[test]
fn the_boundary_names_the_windows_tier_and_its_score() {
    let (sb, project) = installed_with_secret();
    let out = output(
        sb.command().current_dir(&project).args([
            "run",
            "--print-boundary",
            "--format",
            "json",
            "--",
            "cmd",
        ]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let record: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(record["os"], "windows");
    assert_eq!(record["tier"], "lightweight");
    assert_eq!(record["network"]["mode"], "proxy_variables");
    let names: Vec<&str> = record["restrictions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            "restricted_token",
            "job_object",
            "wfp_network",
            "windows_read_deny"
        ]
    );
    assert_eq!(record["score"]["points"], 55, "{record}");
    assert!(
        record["downgrades"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["what"] == "network"),
        "{record}"
    );

    let doctor = sb.moat(&["doctor"]);
    let said = text(&doctor);
    assert!(said.contains("lightweight 55/100"), "{said}");
    assert!(said.contains("wfp_network"), "{said}");

    // A batch file is not started: cmd.exe reads its arguments by its own rules.
    let batch = project.join("agent.cmd");
    std::fs::write(&batch, "@echo ran\r\n").unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .args(["run", "--"])
            .arg(&batch),
        None,
    );
    assert_ne!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stderr(&out).contains("batch file"), "{}", text(&out));
    assert!(!stdout(&out).contains("ran"), "{}", text(&out));
}
