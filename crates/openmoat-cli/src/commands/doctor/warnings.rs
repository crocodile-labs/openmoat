//! `moat doctor` rows that warn without counting as a problem.

use std::fs;

use openmoat_hosts::Host;

use crate::hangs;
use crate::home::Home;
use crate::install::GUARD_BUDGET_S;
use crate::time;

/// The Linux setting that lets a process type into a terminal it shares.
const LEGACY_TIOCSTI: &str = "/proc/sys/dev/tty/legacy_tiocsti";

/// How far back the hang row looks.
const HANG_WINDOW_MS: i64 = 7 * 24 * 3_600_000;

/// The contents of [`LEGACY_TIOCSTI`] on Linux, empty on a kernel without the
/// setting (before 6.2, where `TIOCSTI` is always allowed); `None` elsewhere.
pub(super) fn legacy_tiocsti() -> Option<String> {
    cfg!(target_os = "linux").then(|| fs::read_to_string(LEGACY_TIOCSTI).unwrap_or_default())
}

/// With Codex set up, a warning when `setting` (see [`legacy_tiocsti`]) is not
/// `0`: Codex's Linux sandbox does not refuse `TIOCSTI`, so a sandboxed script
/// could leave a command in the terminal's input that the user's shell runs
/// after the session. Only the kernel stops it.
pub(super) fn tiocsti(codex: bool, setting: Option<&str>) -> Option<String> {
    let value = setting.map(str::trim).filter(|v| codex && *v != "0")?;
    let name = Host::Codex.display_name();
    Some(if value.is_empty() {
        format!(
            "{name:<16} this kernel (before Linux 6.2) always lets a command type into your \
             terminal (TIOCSTI), and Codex's sandbox cannot stop it; a 6.2+ kernel with \
             dev.tty.legacy_tiocsti=0 does"
        )
    } else {
        format!(
            "{name:<16} dev.tty.legacy_tiocsti is {value}: Codex's sandbox cannot stop a command \
             typing into your terminal (TIOCSTI); `sudo sysctl dev.tty.legacy_tiocsti=0` turns that off"
        )
    })
}

/// Calls the guard denied in the last week because no decision came in time.
pub(super) fn hangs(home: &Home, now_ms: i64) -> Option<String> {
    let path = home.hangs_path();
    let found = hangs::since(&path, now_ms - HANG_WINDOW_MS)?;
    let phase = found.common_phase.map_or_else(String::new, |p| {
        format!(", most while {} (phase {})", p.doing(), p.name())
    });
    Some(format!(
        "guard            {} call(s) denied with no decision within {GUARD_BUDGET_S} s \
         in the last 7 days, the latest at {}{phase}; not in the audit log, listed in {}",
        found.count,
        time::timestamp(found.newest_ms),
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiocsti_warns_only_for_codex_on_a_kernel_that_allows_it() {
        let warning = tiocsti(true, Some("1\n")).unwrap();
        assert!(warning.contains("legacy_tiocsti is 1:"), "{warning}");
        assert!(
            warning.contains("sysctl dev.tty.legacy_tiocsti=0"),
            "{warning}"
        );
        assert_eq!(tiocsti(true, Some("0\n")), None);
        assert_eq!(tiocsti(true, None), None, "not Linux");
        let old_kernel = tiocsti(true, Some("")).unwrap();
        assert!(old_kernel.contains("before Linux 6.2"), "{old_kernel}");
        assert_eq!(tiocsti(false, Some("1\n")), None);
    }

    #[test]
    fn hangs_older_than_a_week_are_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().to_path_buf());
        let now = HANG_WINDOW_MS * 2;
        assert_eq!(hangs(&home, now), None);
        fs::write(home.hangs_path(), format!("1 codex\n{now} cursor\n")).unwrap();
        let row = hangs(&home, now).unwrap();
        assert!(row.contains("1 call(s) denied"), "{row}");
        assert!(!row.contains("most while"), "{row}");
        fs::write(
            home.hangs_path(),
            format!("{now} codex taint 30010\n{now} cursor\n"),
        )
        .unwrap();
        let row = hangs(&home, now).unwrap();
        assert!(row.contains("2 call(s) denied"), "{row}");
        assert!(
            row.contains("most while reading the session's earlier calls (phase taint)"),
            "{row}"
        );
    }
}
