use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command};

use rustix::process::{Pid, Signal, kill_process_group};

pub(in super::super) fn own(command: &mut Command) -> &mut Command {
    command.process_group(0)
}

pub(super) fn stop(child: &mut Child) {
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.kill();
}
