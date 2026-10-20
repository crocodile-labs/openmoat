//! The macOS version, read from the file the system keeps it in, so no program
//! runs. `moat doctor --bundle` names it; `moat run` and `moat doctor` compare it
//! with the oldest macOS whose `sandbox-exec` reads the Seatbelt profile.

/// Where macOS keeps its version.
const SYSTEM_VERSION: &str = "/System/Library/CoreServices/SystemVersion.plist";

/// The oldest macOS whose `sandbox-exec` knows `TIOCSTI`, which the Seatbelt
/// profile always denies (`crate::sandbox::seatbelt`). Older ones stop at the
/// profile with `unbound variable: TIOCSTI`.
const RUN_MIN_MACOS: u32 = 13;

/// `ProductVersion` of this Mac (`14.5`); `None` on other systems or when it
/// cannot be read.
pub fn macos() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let plist = std::fs::read_to_string(SYSTEM_VERSION).ok()?;
    product_version(&plist)
}

/// The `ProductVersion` string of a `SystemVersion.plist`.
pub fn product_version(plist: &str) -> Option<String> {
    let after = plist.split_once("<key>ProductVersion</key>")?.1;
    let value = after.split_once("<string>")?.1.split_once("</string>")?.0;
    Some(value.trim().to_owned()).filter(|v| !v.is_empty())
}

/// Why `moat run` cannot start on a Mac with `version`, as the rest of a
/// sentence about `moat run`; `None` when it can. A version that cannot be read
/// or understood is no reason to refuse: `moat run` tries, and `sandbox-exec`
/// still refuses a profile it cannot read, so nothing runs unconfined.
pub fn run_floor(version: Option<&str>) -> Option<String> {
    let version = version?;
    let major: u32 = version.split('.').next()?.trim().parse().ok()?;
    (major < RUN_MIN_MACOS).then(|| {
        format!(
            "needs macOS {RUN_MIN_MACOS} or later; this Mac has macOS {version}, whose \
             `sandbox-exec` cannot read the sandbox profile"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_from_the_plist() {
        let plist = "<dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t\
                     <key>ProductVersion</key>\n\t<string>14.5</string>\n</dict>";
        assert_eq!(product_version(plist).as_deref(), Some("14.5"));
        let blank = "<key>ProductVersion</key><string> </string>";
        assert_eq!(product_version(blank), None);
        assert_eq!(product_version("<dict></dict>"), None);
    }

    #[test]
    fn moat_run_refuses_before_macos_13_only() {
        let refusal = run_floor(Some("12.7")).unwrap();
        assert!(refusal.contains("needs macOS 13 or later"), "{refusal}");
        assert!(refusal.contains("macOS 12.7"), "{refusal}");
        assert_eq!(run_floor(Some("13.0")), None);
        assert_eq!(run_floor(Some("14.5")), None);
        assert_eq!(run_floor(Some("26.1")), None);
    }

    #[test]
    fn an_unreadable_version_lets_moat_run_try() {
        assert_eq!(run_floor(None), None);
        assert_eq!(run_floor(Some("unknown")), None);
        assert_eq!(run_floor(Some("")), None);
    }
}
