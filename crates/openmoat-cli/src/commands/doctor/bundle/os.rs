//! The operating system the bundle names: family, architecture and version.
//! The version is read from the files the system keeps it in, so no program
//! runs; where there is no such file (Windows) it is left out.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct System {
    /// `macos`, `linux`, `windows`.
    os: &'static str,
    /// `aarch64`, `x86_64`.
    arch: &'static str,
    /// `macOS 14.5`, `Ubuntu 24.04.1 LTS (kernel 6.8.0-45-generic)`; `None` where it cannot be read.
    version: Option<String>,
}

impl System {
    pub(super) fn this() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            version: version(),
        }
    }
}

#[cfg(target_os = "macos")]
fn version() -> Option<String> {
    // Where macOS keeps its version.
    let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist").ok()?;
    macos_version(&plist).map(|v| format!("macOS {v}"))
}

#[cfg(target_os = "linux")]
fn version() -> Option<String> {
    // Where a distribution names itself, and where the kernel gives its release.
    let name = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| pretty_name(&text));
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|k| k.trim().to_owned())
        .filter(|k| !k.is_empty());
    match (name, kernel) {
        (Some(name), Some(kernel)) => Some(format!("{name} (kernel {kernel})")),
        (Some(name), None) => Some(name),
        (None, Some(kernel)) => Some(format!("Linux kernel {kernel}")),
        (None, None) => None,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn version() -> Option<String> {
    None
}

/// The `ProductVersion` string of a `SystemVersion.plist`.
#[cfg_attr(
    not(any(target_os = "macos", test)),
    expect(dead_code, reason = "read on macOS only")
)]
fn macos_version(plist: &str) -> Option<String> {
    let after = plist.split_once("<key>ProductVersion</key>")?.1;
    let value = after.split_once("<string>")?.1.split_once("</string>")?.0;
    Some(value.trim().to_owned()).filter(|v| !v.is_empty())
}

/// `PRETTY_NAME` of an `os-release` file, without its quotes.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(dead_code, reason = "read on Linux only")
)]
fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?.trim();
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        Some(value.to_owned()).filter(|v| !v.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_versions_are_read_from_the_system_files() {
        let plist = "<dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t\
                     <key>ProductVersion</key>\n\t<string>14.5</string>\n</dict>";
        assert_eq!(macos_version(plist).as_deref(), Some("14.5"));
        let release = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
        assert_eq!(pretty_name(release).as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(pretty_name("ID=alpine\n"), None);
    }
}
