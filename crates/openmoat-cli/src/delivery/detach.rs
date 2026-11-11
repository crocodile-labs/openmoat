//! A delivery run the guard starts must outlive the guard and hold nothing
//! of the hook's: no standard stream (the host waits for those to close), and
//! on its own process group, so a host that ends the hook's group once it
//! answered does not end the delivery with it.

use std::process::{Command, Stdio};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Set `command` up to run detached from this process.
pub fn detach(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unix::own_group(command);
    #[cfg(windows)]
    windows::own_group(command);
}
