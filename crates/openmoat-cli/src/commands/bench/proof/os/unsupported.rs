//! The OS sandbox layer where the bench has no backend: every OS row is NOT
//! TESTED HERE. On Windows `openmoat run` has a preview tier that holds
//! writes only (ADR-115), and the bench's attacks are POSIX shell scripts.

pub const BACKEND: Option<&str> = None;

/// Never run: no command runs without a backend.
pub const READ_PARENT: &str = "";
