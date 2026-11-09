//! Without Unix modes (Windows): who may change a file is its access control
//! list, which this check does not read; the doctor says so once.

use std::path::Path;

use super::Found;

/// The note `doctor` shows instead of the rows.
pub(super) const NOT_CHECKED: &str = "state files      modes and owners are not checked on this \
                                      system (its files have access control lists, not Unix \
                                      modes)";

/// No user to compare owners with here.
pub(super) fn current_user() -> Option<u32> {
    None
}

/// Never called: [`current_user`] answers `None`.
pub(super) fn inspect(_: &Path, _: u32) -> Option<Found> {
    None
}
