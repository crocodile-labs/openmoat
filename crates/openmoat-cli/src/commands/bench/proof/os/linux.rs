//! The OS sandbox layer on Linux: Landlock and seccomp under `openmoat run`.

pub const BACKEND: Option<&str> = Some("Landlock + seccomp");

/// A child reading its parent's environment and memory through `/proc`.
pub const READ_PARENT: &str = "cat /proc/$PPID/environ; cat /proc/$PPID/mem 2>&1 | head -c 4096";
