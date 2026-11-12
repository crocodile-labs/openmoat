//! Agents OpenMoat writes no OS sandbox for (ADR-076): `status` and `doctor`
//! name the way to one, and on Linux and macOS 13 or later each agent's launch
//! shape holds under `openmoat run`. The agents are stand-ins named as each
//! real one; the sandbox and the relay are the real ones.

use openmoat_hosts::{Host, RunFacts};
use serde_json::Value;

use crate::common::{Sandbox, json as json_of, stdout, text};
use crate::hosts::dir_of;

fn hook_only() -> impl Iterator<Item = Host> {
    Host::ALL
        .into_iter()
        .filter(|host| host.spec().sandbox.is_none())
}

/// `host`'s entry in `status --format json`.
fn entry(sb: &Sandbox, host: Host) -> Value {
    let status = json_of(&sb.moat(&["status", "--format", "json"]));
    status["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["host"] == host.id())
        .unwrap_or_else(|| panic!("no entry for {host}: {status}"))
        .clone()
}

#[test]
fn status_and_doctor_name_the_way_to_a_sandbox_or_why_there_is_none() {
    for host in hook_only() {
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let agent = entry(&sb, host);
        assert_eq!(agent["level"], "hook-only", "{host}: {agent}");
        let sandbox = &agent["os_sandbox"];
        let state = sandbox["state"].as_str().unwrap_or_default();
        match host.spec().run {
            RunFacts::Unknown { why } if state != "unavailable" => {
                assert_eq!(state, "unknown", "{host}: {sandbox}");
                assert_eq!(sandbox["why"], why, "{host}");
            }
            RunFacts::Known { program, .. } if state == "command" => {
                let command = sandbox["command"].as_str().unwrap_or_default();
                assert!(command.starts_with("openmoat run"), "{host}: {command}");
                assert!(command.contains(" --write "), "{host}: {command}");
                assert!(command.ends_with(&format!("-- {program}")), "{command}");
            }
            // Windows, macOS before 13, Linux without a network namespace.
            _ => {
                assert_eq!(state, "unavailable", "{host}: {sandbox}");
                assert!(sandbox["why"].is_string(), "{host}: {sandbox}");
            }
        }
        let shown = stdout(&sb.moat(&["doctor"]));
        let line = shown.split_whitespace().collect::<Vec<_>>().join(" ");
        let said = [
            "OS sandbox:",
            "no OS sandbox on this system:",
            "no `openmoat run`",
        ]
        .iter()
        .any(|text| line.contains(text));
        assert!(said, "{host}: {}", text(&sb.moat(&["doctor"])));
    }
}

/// The launch shape of each agent with known facts, under the real sandbox.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod launch {
    use std::path::{Path, PathBuf};
    use std::process::Output;

    use openmoat_hosts::{Host, RunFacts, RunWrite};

    use super::{dir_of, hook_only};
    use crate::common::{DENY, Sandbox, USAGE, fixture, output, stderr, stdout, text};
    use crate::hosts::row;
    use crate::run::confined::ran;
    use crate::run::{installed_with_secret, netns_required};

    /// `write` below the home, for `host`.
    fn below_home(host: Host, write: RunWrite) -> PathBuf {
        match write {
            RunWrite::ConfigDir => PathBuf::from(dir_of(host)),
            RunWrite::Home(path) => PathBuf::from(path),
            RunWrite::Cache(name) if cfg!(target_os = "macos") => {
                Path::new("Library/Caches").join(name)
            }
            RunWrite::Cache(name) => Path::new(".cache").join(name),
        }
    }

    /// The stand-in: a program named as the agent that tries what the sandbox
    /// must refuse, writes its own state and runs its hook.
    fn script(sb: &Sandbox, hook: &str, state: &Path) -> String {
        let (home, policy) = (sb.home.display(), sb.home.join(".moat/policy.yaml"));
        format!(
            "#!/bin/sh\n\
             echo x > '{home}/outside-the-project'; echo outside=$?\n\
             echo x >> '{policy}'; echo policy=$?\n\
             echo x > '{state}'; echo state=$?\n\
             printf '%s' \"$PAYLOAD\" | ./moat-bin guard --host {hook} > hook.out; echo hook=$?\n\
             cat hook.out\n",
            policy = policy.display(),
            state = state.display()
        )
    }

    fn run(
        sb: &Sandbox,
        project: &Path,
        flags: &[&str],
        writes: &[PathBuf],
        program: &str,
        args: &[&str],
        payload: &str,
    ) -> Output {
        let tmp = sb.home.with_file_name("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let mut cmd = sb.command();
        cmd.current_dir(project)
            .env("TMPDIR", &tmp)
            .env("PAYLOAD", payload)
            .arg("run")
            .args(flags);
        for path in writes {
            cmd.arg("--write").arg(path);
        }
        output(cmd.arg("--").arg(format!("./{program}")).args(args), None)
    }

    /// False, saying so, where this machine cannot start the agent: only a
    /// machine CI does not require a sandbox of.
    fn started(out: &Output) -> bool {
        if out.status.code() == Some(USAGE) && !netns_required() {
            eprintln!("skipped: {}", stderr(out));
            return false;
        }
        ran(out)
    }

    fn launch_holds(host: Host, flags: &[&str]) {
        let RunFacts::Known {
            program,
            args,
            writes,
        } = host.spec().run
        else {
            return;
        };
        let (sb, project) = installed_with_secret();
        let row = row(host.id());
        std::fs::copy(env!("CARGO_BIN_EXE_openmoat"), project.join("moat-bin")).unwrap();
        let dirs: Vec<PathBuf> = writes
            .iter()
            .map(|write| sb.home.join(below_home(host, *write)))
            .collect();
        for dir in &dirs {
            std::fs::create_dir_all(dir).unwrap();
        }
        let policy_before = std::fs::read(sb.home.join(".moat/policy.yaml")).unwrap();
        let state = dirs[0].join("agent-state");
        let agent = project.join(program);
        std::fs::write(&agent, script(&sb, row.hook, &state)).unwrap();
        make_executable(&agent);

        let payload = match row.secret_read {
            Some(read) => read(&sb),
            None => fixture(row.governed),
        };
        let out = run(&sb, &project, flags, &dirs, program, args, &payload);
        if !started(&out) {
            return;
        }
        let shown = text(&out);
        let said = stdout(&out);
        assert!(
            said.contains("outside=") && !said.contains("outside=0"),
            "{host}: {shown}"
        );
        assert!(
            said.contains("policy=") && !said.contains("policy=0"),
            "{host}: {shown}"
        );
        assert!(said.contains("state=0"), "{host}: {shown}");
        assert!(
            !sb.home.join("outside-the-project").exists(),
            "{host}: {shown}"
        );
        assert_eq!(
            std::fs::read(sb.home.join(".moat/policy.yaml")).unwrap(),
            policy_before,
            "{host}: the policy changed"
        );
        assert!(state.exists(), "{host}: its own state: {shown}");

        // The hook's call reached the run, which decided it outside the sandbox.
        assert!(!shown.contains("kernel-error"), "{host}: {shown}");
        assert!(!shown.contains("did not decide"), "{host}: {shown}");
        if row.secret_read.is_some() {
            assert!(said.contains(&format!("hook={DENY}")), "{host}: {shown}");
            assert!(shown.contains("secrets-paths"), "{host}: {shown}");
        }
        let audit = text(&sb.moat(&["show", "--recent", "20", "--format", "json"]));
        assert!(
            audit.contains(&format!("\"host\":\"{}\"", row.hook))
                || audit.contains(&format!("\"host\": \"{}\"", row.hook)),
            "{host}: no row for the hook: {audit}"
        );
    }

    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // protection: run no-own-sandbox linux,macos
    #[test]
    fn each_hook_only_agent_holds_under_openmoat_run() {
        for host in hook_only() {
            // The Lightweight tier; the Isolated one, Linux's default, below.
            launch_holds(host, &["--no-isolate"]);
        }
    }

    /// The command `status` names on Linux.
    // protection: run no-own-sandbox linux
    #[cfg(target_os = "linux")]
    #[test]
    fn each_hook_only_agent_holds_under_isolate() {
        for host in hook_only() {
            launch_holds(host, &["--isolate"]);
        }
    }
}
