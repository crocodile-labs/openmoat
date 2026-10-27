//! Human-only commands refuse when an agent started them, terminal or not.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::common::{OK, Sandbox, output, stderr};

/// A shell script named `name` in the sandbox's home that runs its arguments
/// as a command and stays their parent (`ps` shows `/bin/sh <dir>/<name> …`,
/// whose second word names the agent). A script, not a copy of the system
/// shell: macOS 26 kills a copy of one of its own binaries run from outside
/// the system volume (exit 137).
fn stand_in(home: &Path, name: &str) -> PathBuf {
    let path = home.join(name);
    std::fs::write(&path, "#!/bin/sh\n\"$@\"\nexit $?\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A script named `claude` stands in for the agent: every command it starts
/// descends from a process named like Claude Code, as a command the agent
/// runs through a pty wrapper would.
#[test]
fn a_human_only_command_started_by_an_agent_is_refused() {
    let sb = Sandbox::installed(&[".claude"]);
    let agent = stand_in(&sb.home, "claude");
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
        // The script's `exit $?` keeps it from replacing itself with `moat`.
        let mut cmd = sb.configure(Command::new(&agent));
        cmd.arg(moat).args(args);
        let out = output(&mut cmd, None);
        let err = stderr(&out);
        assert_ne!(out.status.code(), Some(OK), "{args:?}: {err}");
        assert!(err.contains("not by an agent"), "{args:?}: {err}");
        assert!(err.contains("`claude`"), "{args:?}: {err}");
    }

    // A shell of another name is not taken for an agent. (When the test suite
    // itself runs under an agent, that agent is still found further up.)
    let shell = stand_in(&sb.home, "sh");
    let mut cmd = sb.configure(Command::new(&shell));
    cmd.args([moat, "allow", "--last"]);
    let out = output(&mut cmd, None);
    let err = stderr(&out);
    assert_ne!(out.status.code(), Some(OK), "no terminal: {err}");
    assert!(!err.contains("started from `sh`"), "{err}");
}
