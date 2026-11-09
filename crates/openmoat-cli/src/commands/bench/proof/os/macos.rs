//! The OS sandbox layer on macOS: Seatbelt under `openmoat run`.

use std::path::Path;

pub const BACKEND: Option<&str> = Some("Seatbelt");

/// A child reading its parent's environment: the `KERN_PROCARGS2` sysctl.
pub const READ_PARENT: &str = "/bin/ps eww -p $PPID";

/// Seatbelt denies inside the trees it grants, so where the home is
/// changes nothing; there is no hint to give.
pub fn hint(_home: &Path) -> String {
    String::new()
}
