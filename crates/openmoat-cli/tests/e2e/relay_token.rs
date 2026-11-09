//! The relay token and what tool commands can reach (ADR-075). The scripts
//! stand in for an agent that holds the run's environment; the sandbox is the
//! real one.

use std::path::Path;
use std::process::Output;

use crate::common::{stdout, text};
use crate::run::confined::ran;
use crate::run::{installed_with_secret, run_sh_with};

/// What the "agent" writes down: the token its own environment holds.
const TOKEN_FILE: &str = "agent-token.txt";

/// The agent's script: it records its token, then starts a child (the tool
/// command) that runs `attack` and prints what it found. The trailing `true`
/// keeps the shell from replacing itself with the child, so the child's parent
/// process is the agent.
fn agent_starting(attack: &str) -> String {
    format!(
        "printf '%s' \"$MOAT_GUARD_TOKEN\" > {TOKEN_FILE}\n\
         /bin/sh -c '{attack}'\n\
         true\n"
    )
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
