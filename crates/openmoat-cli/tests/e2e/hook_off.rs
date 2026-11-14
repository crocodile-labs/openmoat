//! A repository that turns the agent's OpenMoat hook off as a session starts
//! (ADR-095): `openmoat run` refuses to start the agent over it, for every
//! host whose spec says a project can, while a project that turns nothing off
//! is not refused; and `openmoat init --managed` puts OpenMoat's hook where an
//! administrator's hooks live, which a project cannot turn off, printing the
//! command where that needs root. Every host fact comes from its spec; the
//! "agent" is an empty file named as the host's program, which never runs,
//! and the system directories are a folder of the test's
//! (`MOAT_TEST_SYSTEM_ROOT`, honoured by debug builds only).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use openmoat_hosts::{Host, Managed, ManagedHooks, Platform, ProjectFile, ProjectOff};

use crate::common::{OK, Sandbox, USAGE, output, stderr, text};
use crate::hosts::dir_of;

/// The variable debug builds read the system directories under.
const SYSTEM_ROOT: &str = "MOAT_TEST_SYSTEM_ROOT";
/// What `openmoat run` says when it refuses (`commands/run/hook_off.rs`).
const REFUSED: &str = "does not start";

/// Each host whose spec gives a project file that turns its hook off.
fn examples() -> Vec<(Host, ProjectFile)> {
    Host::ALL
        .into_iter()
        .filter_map(|host| match host.spec().hook_off.project {
            ProjectOff::Files { example, .. } => Some((host, example)),
            ProjectOff::Nothing { .. } => None,
        })
        .collect()
}

/// `host` set up in a fresh home, and the home's system directory.
fn set_up(host: Host) -> (Sandbox, PathBuf) {
    let sb = Sandbox::installed(&[&dir_of(host)]);
    let system = sb.home.with_file_name("system");
    fs::create_dir_all(&system).unwrap();
    (sb, system)
}

/// An empty file named as `host`'s program, outside the home: `openmoat
/// run` tells the agent by its name and refuses before starting anything.
fn fake_agent(sb: &Sandbox, host: Host) -> PathBuf {
    let bin = sb.home.with_file_name("bin");
    fs::create_dir_all(&bin).unwrap();
    let agent = bin.join(host.spec().process.names[0]);
    fs::write(&agent, "").unwrap();
    agent
}

fn write(project: &Path, file: &ProjectFile, text: &str) {
    let path = project.join(file.path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// `openmoat run -- <agent> [args]` in `project`.
fn run(sb: &Sandbox, system: &Path, project: &Path, agent: &Path, args: &[&str]) -> Output {
    let tmp = sb.home.with_file_name("tmp");
    fs::create_dir_all(&tmp).unwrap();
    output(
        sb.command()
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .env(SYSTEM_ROOT, system)
            .arg("run")
            .arg("--")
            .arg(agent)
            .args(args),
        None,
    )
}

/// The platform whose files these tests look for (Linux and WSL share them).
fn platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

/// Where `hooks`' file is under the test's system directory `system`.
fn managed_file(hooks: &ManagedHooks, system: &Path) -> PathBuf {
    let file = hooks
        .files
        .iter()
        .find(|f| f.platforms.contains(&platform()))
        .unwrap();
    let rel = file.path.split_once(":/").map_or(file.path, |(_, r)| r);
    system.join(rel.trim_start_matches('/'))
}

/// `openmoat init --managed` as a person at a terminal.
fn init_managed(sb: &Sandbox, system: &Path) -> Output {
    output(
        sb.command()
            .env("MOAT_ASSUME_TTY", "1")
            .env(SYSTEM_ROOT, system)
            .args(["init", "--yes", "--managed", "--no-mcp-proxy"]),
        None,
    )
}

/// The attack: a cloned repository's settings turn the hook off. The run
/// refuses, names the file and the way out, and the agent never starts; in
/// a folder below the project the root's file is found as well.
#[test]
fn run_refuses_a_project_that_turns_the_agents_hook_off() {
    let hosts = examples();
    assert!(hosts.len() >= 7, "{hosts:?}");
    for (host, example) in hosts {
        let id = host.id();
        let (sb, system) = set_up(host);
        let project = sb.project();
        write(&project, &example, example.text);
        let agent = fake_agent(&sb, host);
        for cwd in [project.clone(), project.join("src")] {
            fs::create_dir_all(&cwd).unwrap();
            let out = run(&sb, &system, &cwd, &agent, &[]);
            let shown = text(&out);
            // The host's own option covers some files: those start, with it.
            if host.spec().hook_off.session_override.is_some() {
                assert!(!stderr(&out).contains(REFUSED), "{id}: {shown}");
                // Said with the other notices, once the sandbox is made.
                // (A Linux kernel without Landlock ABI 4 refuses before it.)
                if cfg!(any(target_os = "macos", target_os = "linux"))
                    && !stderr(&out).contains("needs Landlock ABI 4")
                {
                    assert!(stderr(&out).contains("keeps them on"), "{id}: {shown}");
                }
                continue;
            }
            assert_eq!(out.status.code(), Some(USAGE), "{id}: {shown}");
            assert!(stderr(&out).contains(REFUSED), "{id}: {shown}");
            assert!(
                stderr(&out).contains(&example.path.replace('/', std::path::MAIN_SEPARATOR_STR))
                    || stderr(&out).contains(example.path),
                "{id}: {shown}"
            );
            assert!(
                stderr(&out).contains("sandbox.project_hook_off"),
                "{id}: {shown}"
            );
        }
    }
}

/// A host whose option covers the file still refuses when the person's own
/// arguments would take that option's place.
#[test]
fn run_refuses_when_the_persons_own_option_would_replace_the_override() {
    for (host, example) in examples() {
        let Some(over) = &host.spec().hook_off.session_override else {
            continue;
        };
        let (sb, system) = set_up(host);
        let project = sb.project();
        write(&project, &example, example.text);
        let agent = fake_agent(&sb, host);
        let out = run(&sb, &system, &project, &agent, &[over.clashes[0], "{}"]);
        assert_eq!(
            out.status.code(),
            Some(USAGE),
            "{}: {}",
            host.id(),
            text(&out)
        );
        assert!(stderr(&out).contains(REFUSED), "{}", text(&out));
    }
}

/// The benign neighbours: a project whose settings turn nothing off, and
/// the same file in a folder the host never loads, are not refused for it.
#[test]
fn run_does_not_refuse_a_project_that_turns_nothing_off() {
    for (host, example) in examples() {
        let (sb, system) = set_up(host);
        let project = sb.project();
        let nothing = if Path::new(example.path)
            .extension()
            .is_some_and(|e| e == "toml")
        {
            "[features]\nhooks = true\n"
        } else {
            "{}\n"
        };
        write(&project, &example, nothing);
        write(&project.join("fixtures"), &example, example.text);
        let agent = fake_agent(&sb, host);
        let out = run(&sb, &system, &project, &agent, &[]);
        assert!(
            !stderr(&out).contains(REFUSED),
            "{}: {}",
            host.id(),
            text(&out)
        );
    }
}

/// `init --managed` refuses without a person at a terminal, before it
/// writes anything.
#[test]
fn init_managed_needs_a_person_at_a_terminal() {
    let sb = Sandbox::bare(&[]);
    let system = sb.home.with_file_name("system");
    let out = output(
        sb.command()
            .env(SYSTEM_ROOT, &system)
            .args(["init", "--yes", "--managed"]),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("--managed"), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists(), "nothing written");
    assert!(!system.exists());
}

/// Each host with a managed file: `init --managed` writes it where this
/// account may, or keeps it under the state directory with the command
/// that installs it owned by root; once again it is unchanged; `doctor`
/// reports it; and a run over a project that turns the person's hook off
/// starts where the host's documentation says the managed hook outlasts it.
/// `uninstall` takes it away.
#[test]
fn init_managed_writes_the_hook_where_a_project_cannot_turn_it_off() {
    for host in Host::ALL {
        let Managed::Written(hooks) = &host.spec().hook_off.managed else {
            continue;
        };
        let id = host.id();
        let (sb, system) = set_up(host);
        let target = managed_file(hooks, &system);
        let out = init_managed(&sb, &system);
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(OK), "{id}: {shown}");
        let staged = sb.home.join(".moat/managed").join(format!("{id}.json"));
        if hooks.root_owned {
            assert!(!target.exists(), "{id}: written without root");
            assert!(staged.is_file(), "{id}: {shown}");
            let command = if cfg!(windows) {
                "Copy-Item"
            } else {
                "sudo install"
            };
            assert!(shown.contains(command), "{id}: {shown}");
            // Put in place as the command would, so the rest applies.
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(&staged, &target).unwrap();
        } else {
            assert!(target.is_file(), "{id}: {shown}");
        }
        let written = fs::read_to_string(&target).unwrap();
        assert!(written.contains(" guard"), "{id}: {written}");
        assert!(written.contains(id), "{id}: {written}");

        let again = init_managed(&sb, &system);
        assert!(
            text(&again).contains("(unchanged)"),
            "{id}: {}",
            text(&again)
        );

        let doctor = output(sb.command().env(SYSTEM_ROOT, &system).arg("doctor"), None);
        assert!(
            text(&doctor).contains("managed hook"),
            "{id}: {}",
            text(&doctor)
        );

        if let ProjectOff::Files { example, .. } = host.spec().hook_off.project {
            let project = sb.project();
            write(&project, &example, example.text);
            let agent = fake_agent(&sb, host);
            let out = run(&sb, &system, &project, &agent, &[]);
            assert_eq!(
                !stderr(&out).contains(REFUSED),
                hooks.outlasts_project,
                "{id}: {}",
                text(&out)
            );
        }

        let gone = output(
            sb.command()
                .env("MOAT_ASSUME_TTY", "1")
                .env(SYSTEM_ROOT, &system)
                .args(["uninstall", "--hosts", id]),
            None,
        );
        assert_eq!(gone.status.code(), Some(OK), "{id}: {}", text(&gone));
        assert!(!target.exists(), "{id}: {}", text(&gone));
        assert!(!staged.exists(), "{id}");
    }
}

/// A host's one managed file that holds an administrator's own hooks is
/// never edited, nor removed by `uninstall`.
#[test]
fn init_managed_leaves_an_administrators_own_file_alone() {
    for host in Host::ALL {
        let Managed::Written(hooks) = &host.spec().hook_off.managed else {
            continue;
        };
        let (sb, system) = set_up(host);
        let target = managed_file(hooks, &system);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let theirs = "{\"version\": 1, \"hooks\": {\"x\": [{\"command\": \"/opt/audit.sh\"}]}}\n";
        fs::write(&target, theirs).unwrap();
        let out = init_managed(&sb, &system);
        assert_eq!(out.status.code(), Some(OK), "{}: {}", host.id(), text(&out));
        assert!(text(&out).contains("administrator's own"), "{}", text(&out));
        assert_eq!(fs::read_to_string(&target).unwrap(), theirs);
        let gone = output(
            sb.command()
                .env("MOAT_ASSUME_TTY", "1")
                .env(SYSTEM_ROOT, &system)
                .args(["uninstall", "--hosts", host.id()]),
            None,
        );
        assert_eq!(gone.status.code(), Some(OK), "{}", text(&gone));
        assert_eq!(fs::read_to_string(&target).unwrap(), theirs);
    }
}
