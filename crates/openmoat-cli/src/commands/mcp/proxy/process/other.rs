use std::process::{Child, Command};

pub(in super::super) fn own(command: &mut Command) -> &mut Command {
    command
}

pub(super) fn stop(child: &mut Child) {
    let _ = child.kill();
}
