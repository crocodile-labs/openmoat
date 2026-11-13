//! The macOS version, read from the file the system keeps it in, so no program
//! runs. `moat doctor --bundle` names it; `moat run` and `moat doctor` compare it
//! with the oldest macOS whose `sandbox-exec` reads the Seatbelt profile.

// `this_os` is this OS's module: `system()`, the system and its version in
// one line for `describe` (not `platform`, which names the function below).
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as this_os;
#[cfg(target_os = "macos")]
use macos as this_os;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as this_os;

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

/// The system this build runs on, as host advisories name one. Linux under
/// the Windows Subsystem for Linux sets `WSL_DISTRO_NAME` in every session and
/// names Microsoft in its kernel release.
pub fn platform() -> openmoat_hosts::Platform {
    use openmoat_hosts::Platform;
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if std::env::var_os("WSL_DISTRO_NAME").is_some_and(|v| !v.is_empty())
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|release| is_wsl_release(&release))
    {
        Platform::Wsl
    } else {
        Platform::Linux
    }
}

/// What `openmoat doctor` says about the Windows Subsystem for Linux here
/// (ADR-083): on native Windows with `wsl.exe` installed, where OS
/// confinement is; under WSL1, that it has none. Nothing runs: the kernel
/// release and the launcher's file are read.
pub fn wsl_note() -> Option<String> {
    let platform = platform();
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
    let launcher = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .is_some_and(|root| root.join("System32").join("wsl.exe").is_file());
    wsl_note_for(platform, release.as_deref(), launcher)
}

/// [`wsl_note`] for `platform`, its kernel `release` and whether WSL's
/// launcher is installed.
fn wsl_note_for(
    platform: openmoat_hosts::Platform,
    release: Option<&str>,
    launcher: bool,
) -> Option<String> {
    use openmoat_hosts::Platform;
    match platform {
        Platform::Windows if launcher => Some(
            "WSL              installed: for OS confinement install OpenMoat inside a WSL2 \
             distribution and run the agent there; from Windows the hook denies commands and \
             paths that cross into WSL (`wsl-crossing`)"
                .to_owned(),
        ),
        // WSL1 has no kernel: its release is `4.4.0-<Windows build>-Microsoft`.
        // WSL2's real kernel, a custom one included, reads otherwise.
        Platform::Wsl
            if release.is_some_and(|r| {
                let r = r.trim();
                r.starts_with("4.4.0-") && r.ends_with("-Microsoft")
            }) =>
        {
            Some(
                "WSL              WSL1 has no Linux kernel of its own: `openmoat run` and the \
                 agents' sandboxes need WSL2 (`wsl --set-version <distribution> 2`)"
                    .to_owned(),
            )
        }
        _ => None,
    }
}

/// This system and its version in one line, for `openmoat bench --report`:
/// `macOS 14.5 (aarch64)`, `Ubuntu 24.04.1 LTS, Linux 6.8.0-1017-azure
/// (x86_64)`; read from files, so no program runs. Parts that cannot be read
/// are said to be unknown.
pub fn describe() -> String {
    format!("{} ({})", this_os::system(), std::env::consts::ARCH)
}

/// `PRETTY_NAME` of an `os-release` file, unquoted. Kept here, not in
/// `linux.rs`, so its tests run on every system.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(dead_code, reason = "only Linux reads an os-release file")
)]
pub fn pretty_name(os_release: &str) -> Option<String> {
    let line = os_release
        .lines()
        .find_map(|l| l.trim().strip_prefix("PRETTY_NAME="))?;
    let name = line.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    Some(name.to_owned()).filter(|n| !n.is_empty())
}

/// Whether a Linux kernel release string is the Windows Subsystem for
/// Linux's (`5.15.153.1-microsoft-standard-WSL2`).
fn is_wsl_release(release: &str) -> bool {
    let release = release.to_ascii_lowercase();
    release.contains("microsoft") || release.contains("wsl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_is_told_by_its_kernel_release() {
        assert!(is_wsl_release("5.15.153.1-microsoft-standard-WSL2\n"));
        assert!(is_wsl_release("4.4.0-19041-Microsoft"));
        assert!(!is_wsl_release("6.8.0-45-generic"));
    }

    #[test]
    fn wsl_is_named_where_it_changes_what_protects() {
        use openmoat_hosts::Platform;
        let windows = wsl_note_for(Platform::Windows, None, true).unwrap();
        assert!(windows.contains("inside a WSL2"), "{windows}");
        assert!(windows.contains("wsl-crossing"), "{windows}");
        assert_eq!(wsl_note_for(Platform::Windows, None, false), None);
        let wsl1 = wsl_note_for(Platform::Wsl, Some("4.4.0-19041-Microsoft\n"), false).unwrap();
        assert!(wsl1.contains("need WSL2"), "{wsl1}");
        let wsl2 = Some("5.15.153.1-microsoft-standard-WSL2\n");
        assert_eq!(wsl_note_for(Platform::Wsl, wsl2, false), None);
        assert_eq!(
            wsl_note_for(Platform::Linux, Some("6.8.0-45-generic"), false),
            None
        );
        assert_eq!(wsl_note_for(Platform::MacOs, None, true), None);
    }

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
