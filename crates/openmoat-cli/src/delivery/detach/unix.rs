use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// A process group of its own (`setpgid(0, 0)` in the child).
pub fn own_group(command: &mut Command) {
    command.process_group(0);
}
