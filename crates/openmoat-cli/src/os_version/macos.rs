//! The macOS version, from `SystemVersion.plist` ([`super::macos()`]).

/// `macOS 14.5`, or the version said to be unknown.
pub fn system() -> String {
    format!(
        "macOS {}",
        super::macos().unwrap_or_else(|| "(version unknown)".to_owned())
    )
}
