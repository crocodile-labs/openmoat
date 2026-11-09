//! The OS sandbox layer on macOS: Seatbelt under `openmoat run`.

pub const BACKEND: Option<&str> = Some("Seatbelt");

/// A child reading its parent's environment: the `KERN_PROCARGS2` sysctl.
pub const READ_PARENT: &str = "/bin/ps eww -p $PPID";
