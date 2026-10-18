//! Other systems (Windows): the parent processes are not read yet, so only
//! the terminal check applies to the human-only commands.

use std::io;

pub(super) fn agent_ancestor() -> io::Result<Option<String>> {
    // Pid 0 ends the walk at once: no parent is known here.
    super::walk(0, |_| {
        Err(io::Error::other(
            "parent processes are not read on this system",
        ))
    })
}
