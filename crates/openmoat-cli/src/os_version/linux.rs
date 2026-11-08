//! The Linux distribution and kernel release, from `/etc/os-release` and
//! `/proc`, so no program runs.

/// `Ubuntu 24.04.1 LTS, Linux 6.8.0-1017-azure`; parts that cannot be read
/// are left out or said to be unknown.
pub fn system() -> String {
    let distribution = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| super::pretty_name(&text));
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| "(kernel unknown)".to_owned(), |k| k.trim().to_owned());
    match distribution {
        Some(name) => format!("{name}, Linux {kernel}"),
        None => format!("Linux {kernel}"),
    }
}
