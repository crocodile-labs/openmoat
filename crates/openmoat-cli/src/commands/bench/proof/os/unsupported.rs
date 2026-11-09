//! The OS sandbox layer where `openmoat run` refuses (#135): no backend, so
//! every OS row is NOT TESTED HERE.

use std::path::Path;

pub const BACKEND: Option<&str> = None;

/// Never run: no command runs without a backend.
pub const READ_PARENT: &str = "";

/// Never reached: no command runs without a backend.
pub fn hint(_home: &Path) -> String {
    String::new()
}
