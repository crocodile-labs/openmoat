//! Systems whose version OpenMoat does not read (Windows): the name only.

/// `windows (version unknown)`.
pub fn system() -> String {
    format!("{} (version unknown)", std::env::consts::OS)
}
