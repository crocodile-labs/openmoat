//! Windows and other systems: no process group; the server itself is killed.

use std::process::{Child, Command};

/// The server's command as it is.
pub(in super::super) fn own(command: &mut Command) -> &mut Command {
    command
}

/// No signal to ask with: the server is killed.
pub(super) fn terminate(child: &mut Child) {
    let _ = child.kill();
}

/// Kill the server.
pub(super) fn kill(child: &mut Child) {
    let _ = child.kill();
}
