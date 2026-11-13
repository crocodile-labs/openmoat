//! Neither Unix nor Windows: no modes or access lists are read; the doctor
//! says so once.

use std::path::Path;

use super::Found;
use crate::commands::doctor::rows::Report;
use crate::home::Home;

/// Nothing is read of the directory here.
pub(super) fn directory(_: &mut Report, _: &Home) {}

/// The note `doctor` shows instead of the rows.
pub(super) const NOT_CHECKED: &str = "state files      modes and owners are not checked on this \
                                      system (its files have no Unix \
                                      modes)";

/// No user to compare owners with here.
pub(super) fn current_user() -> Option<u32> {
    None
}

/// Never called: [`current_user`] answers `None`.
pub(super) fn inspect(_: &Path, _: u32) -> Option<Found> {
    None
}
