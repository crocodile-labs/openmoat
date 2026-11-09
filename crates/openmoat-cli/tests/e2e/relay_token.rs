//! The relay token and what tool commands can reach (ADR-075). The scripts
//! stand in for an agent that holds the run's environment; the sandbox and
//! the wrapper are the real ones.

use std::path::Path;
use std::process::Output;

use openmoat_hosts::{Host, ToolToken};

use crate::common::{DENY, Sandbox, bash_payload, output, stdout, text};
use crate::run::confined::ran;
use crate::run::{installed_with_secret, run_sh_with};

/// What the "agent" writes down: the token its own environment holds.
const TOKEN_FILE: &str = "agent-token.txt";

/// A script that records the token the agent holds.
const RECORD_TOKEN: &str = "printf '%s' \"$MOAT_GUARD_TOKEN\" > agent-token.txt\n";

/// The agent's script: it records its token, then starts a child (the tool
/// command) that runs `attack` and prints what it found. The trailing `true`
/// keeps the shell from replacing itself with the child, so the child's parent
/// process is the agent.
fn agent_starting(attack: &str) -> String {
    format!("{RECORD_TOKEN}/bin/sh -c '{attack}'\ntrue\n")
}

/// The token the agent held, which must not be empty for the test to mean
/// anything.
fn token_of(project: &Path, out: &Output) -> String {
    let token = std::fs::read_to_string(project.join(TOKEN_FILE)).unwrap_or_default();
    assert_eq!(
        token.len(),
        64,
        "the agent held no relay token: {}",
        text(out)
    );
    token
}

/// What a tool command runs to read its parent's environment on this OS: the
/// file on Linux, the `KERN_PROCARGS2` sysctl through `ps` on macOS.
const READ_PARENT: &str = if cfg!(target_os = "linux") {
    "cat /proc/$PPID/environ; cat /proc/$PPID/mem 2>&1 | head -c 4096"
} else {
    "/bin/ps eww -p $PPID"
};

#[test]
fn a_tool_command_cannot_read_the_token_from_its_parent() {
    let (sb, project) = installed_with_secret();
    let out = run_sh_with(&sb, &project, &agent_starting(READ_PARENT), &[]);
    if !ran(&out) {
        return;
    }
    let token = token_of(&project, &out);
    assert!(
        !stdout(&out).contains(&token),
        "a tool command read the agent's relay token from its parent: {}",
        text(&out)
    );
}

/// An executable named as `host`'s program, in the project: `body` is its
/// script, the stand-in for that agent.
fn fake_agent(project: &Path, host: Host, body: &str) -> String {
    let name = host.spec().process.names[0];
    let script = project.join(name);
    std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
    make_executable(&script);
    name.to_owned()
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `openmoat run -- ./<agent>` in `project`.
fn run_agent(sb: &Sandbox, project: &Path, agent: &str, env: &[(&str, &str)]) -> Output {
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    output(
        sb.command()
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .envs(env.iter().copied())
            .args(["run", "--"])
            .arg(format!("./{agent}")),
        None,
    )
}

/// Each host whose tool shell the run takes over with a wrapper, with the
/// first variable it reads the shell from.
fn wrapped() -> Vec<(Host, &'static str)> {
    Host::EVERY
        .into_iter()
        .filter_map(|host| match host.spec().tool_token {
            ToolToken::Wrapper { vars, .. } => Some((host, vars[0])),
            _ => None,
        })
        .collect()
}

/// A tool command as the agent starts it, through the shell in `var`.
fn tool(var: &str, command: &str) -> String {
    format!("\"${var}\" -c '{command}'\n")
}

/// The relay variables a command sees, as one line each.
const SHOW_RELAY: &str = "echo socket=${MOAT_GUARD_SOCKET-unset} token=${MOAT_GUARD_TOKEN-unset}";

#[test]
fn a_tool_command_has_neither_variable_for_every_wrapped_host() {
    for (host, var) in wrapped() {
        let (sb, project) = installed_with_secret();
        let script = format!("{RECORD_TOKEN}{}", tool(var, SHOW_RELAY));
        let agent = fake_agent(&project, host, &script);
        let out = run_agent(&sb, &project, &agent, &[]);
        if !ran(&out) {
            return;
        }
        let token = token_of(&project, &out);
        assert!(
            stdout(&out).contains("socket=unset token=unset"),
            "{}: {}",
            host.id(),
            text(&out)
        );
        assert!(!stdout(&out).contains(&token), "{}", host.id());
    }
}

#[test]
fn a_nested_shell_has_neither_variable() {
    let (sb, project) = installed_with_secret();
    let (host, var) = wrapped()[0];
    std::fs::write(project.join("nested.sh"), format!("{SHOW_RELAY}\n")).unwrap();
    let script = format!("{RECORD_TOKEN}{}", tool(var, "/bin/sh nested.sh"));
    let agent = fake_agent(&project, host, &script);
    let out = run_agent(&sb, &project, &agent, &[]);
    if !ran(&out) {
        return;
    }
    assert!(
        stdout(&out).contains("socket=unset token=unset"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_script_a_tool_command_runs_cannot_read_its_parent() {
    let (sb, project) = installed_with_secret();
    let (host, var) = wrapped()[0];
    std::fs::write(project.join("script.sh"), format!("{READ_PARENT}\n")).unwrap();
    let script = format!("{RECORD_TOKEN}{}true\n", tool(var, "sh ./script.sh"));
    let agent = fake_agent(&project, host, &script);
    let out = run_agent(&sb, &project, &agent, &[]);
    if !ran(&out) {
        return;
    }
    let token = token_of(&project, &out);
    assert!(!stdout(&out).contains(&token), "{}", text(&out));
}

/// The binary copied into the project, which the sandbox can read.
fn moat_in(project: &Path) {
    let copy = project.join("moat-bin");
    std::fs::copy(env!("CARGO_BIN_EXE_openmoat"), copy).unwrap();
}

#[test]
fn a_hook_still_gets_a_decision_and_a_tool_commands_call_is_refused() {
    let (sb, project) = installed_with_secret();
    moat_in(&project);
    let (host, var) = wrapped()[0];
    let hook = "./moat-bin guard --host claude-code";
    let script = format!(
        "printf '%s' \"$PAYLOAD\" | {hook} > hook.out; echo hook=$?\n{}cat tool.out\n",
        tool(
            var,
            &format!("printf %s \"$PAYLOAD\" | {hook} > tool.out; echo tool=$?")
        ),
    );
    let agent = fake_agent(&project, host, &script);
    let payload = bash_payload("relay-tool", &project, "ls");
    let out = run_agent(&sb, &project, &agent, &[("PAYLOAD", &payload)]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains("hook=0"), "{shown}");
    // Without the token the guard has no relay and cannot read the lock.
    assert!(stdout(&out).contains(&format!("tool={DENY}")), "{shown}");
    assert!(shown.contains("kernel-error"), "{shown}");
}
