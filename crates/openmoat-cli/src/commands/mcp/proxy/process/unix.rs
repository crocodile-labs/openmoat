//! The server in its own process group, so stopping it stops what it started.

use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command};

use rustix::process::{Pid, Signal, kill_process_group};

/// Start the server as the leader of a new process group. A terminal's
/// Ctrl-C then reaches the proxy, not the server, which sees its input close.
pub(in super::super) fn own(command: &mut Command) -> &mut Command {
    command.process_group(0)
}

/// Ask the server's process group to stop.
pub(super) fn terminate(child: &Child) {
    let _ = kill_process_group(Pid::from_child(child), Signal::TERM);
}

/// Kill the server's process group, and the server should it have left it.
pub(super) fn kill(child: &mut Child) {
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.kill();
}
