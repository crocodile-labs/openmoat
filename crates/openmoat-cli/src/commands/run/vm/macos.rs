//! macOS: the tier would use Apple's Virtualization.framework, which boots a
//! Linux guest and shares folders with it (virtiofs) from macOS 12.

/// The first macOS the tier's design covers.
const MIN_MACOS: u32 = 12;

/// The VM monitor this system would use, or why it has none.
pub fn monitor() -> Result<String, String> {
    let version = crate::os_version::macos();
    let major = version
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse::<u32>().ok());
    match (version.as_deref(), major) {
        (Some(v), Some(m)) if m >= MIN_MACOS => {
            Ok(format!("Apple Virtualization.framework (macOS {v})"))
        }
        (Some(v), _) => Err(format!(
            "macOS {v}: Virtualization.framework shares folders with a Linux guest from macOS \
             {MIN_MACOS}"
        )),
        (None, _) => Err("the macOS version cannot be read".to_owned()),
    }
}
