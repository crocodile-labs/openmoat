//! The OS sandbox layer on Linux: Landlock and seccomp under `openmoat run`.

use std::path::Path;

pub const BACKEND: Option<&str> = Some("Landlock + seccomp");

/// A child reading its parent's environment and memory through `/proc`.
pub const READ_PARENT: &str = "cat /proc/$PPID/environ; cat /proc/$PPID/mem 2>&1 | head -c 4096";

/// Landlock cannot deny inside a tree it grants, and `/tmp` is a read root:
/// a throwaway home there cannot be protected, so `openmoat run` refuses.
pub fn hint(home: &Path) -> String {
    if home.starts_with("/tmp") {
        "; the throwaway home is under /tmp, which the sandbox lets commands read: pass \
         --scratch-dir with a directory outside /tmp"
            .to_owned()
    } else {
        String::new()
    }
}
