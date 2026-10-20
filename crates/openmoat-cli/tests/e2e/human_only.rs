//! Human-only commands refuse when an agent started them, terminal or not.

use std::process::Command;

use crate::common::{OK, Sandbox, output, stderr};

/// A shell copied under the name `claude` stands in for the agent: every
/// command it starts descends from a process named like Claude Code, as a
/// command the agent runs through a pty wrapper would.
#[test]
fn a_human_only_command_started_by_an_agent_is_refused() {
    let sb = Sandbox::installed(&[".claude"]);
    let shell = if cfg!(target_os = "macos") {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let agent = sb.home.join("claude");
    std::fs::copy(shell, &agent).unwrap();
    let moat = env!("CARGO_BIN_EXE_openmoat");
    for args in [
        &["allow", "--last"][..],
        &["doctor", "--accept"],
        &["trust"],
        &["edit"],
        &["secret", "add", "TOKEN", "--env", "TOKEN"],
        &["uninstall"],
        &["sandbox", "sync"],
        &["mcp", "accept"],
        &["mcp", "wrap"],
        &["mcp", "unwrap"],
        &["audit", "anchor", "--file", "anchors.jsonl"],
        &["policy", "install", "pack.yaml"],
        &["policy", "trust-key", "key.pub", "--name", "a"],
        &["policy", "remove", "team"],
    ] {
        // `; exit $?` keeps the shell from replacing itself with `moat`.
        let mut cmd = sb.configure(Command::new(&agent));
        cmd.args(["-c", "\"$0\" \"$@\"; exit $?", moat]).args(args);
        let out = output(&mut cmd, None);
        let err = stderr(&out);
        assert_ne!(out.status.code(), Some(OK), "{args:?}: {err}");
        assert!(err.contains("not by an agent"), "{args:?}: {err}");
        assert!(err.contains("`claude`"), "{args:?}: {err}");
    }

    // A shell of another name is not taken for an agent. (When the test suite
    // itself runs under an agent, that agent is still found further up.)
    let shell_copy = sb.home.join("sh");
    std::fs::copy(shell, &shell_copy).unwrap();
    let mut cmd = sb.configure(Command::new(&shell_copy));
    cmd.args(["-c", "\"$0\" \"$@\"; exit $?", moat, "allow", "--last"]);
    let out = output(&mut cmd, None);
    let err = stderr(&out);
    assert_ne!(out.status.code(), Some(OK), "no terminal: {err}");
    assert!(!err.contains("started from `sh`"), "{err}");
}
