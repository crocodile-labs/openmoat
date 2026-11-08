//! Linux: Landlock refuses with `EACCES`, as a file mode does, and under
//! `--isolate` the state directory is not mounted at all (`ENOENT`). What
//! tells the run's sandbox apart is the seccomp filter `openmoat run` applies
//! to the agent and everything it starts, which this process inherits and
//! cannot drop: `/proc/self/status` says `Seccomp: 2` (filter mode).

use std::io;

/// What this process's status says about its confinement.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    /// A seccomp filter is applied (`Seccomp: 2`).
    seccomp_filter: bool,
}

impl Probe {
    /// This process. A status that cannot be read is read as filtered: only
    /// a sandbox keeps a process from its own `/proc/self/status`.
    pub fn system() -> Self {
        let seccomp_filter = match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => seccomp_filtered(&status),
            Err(_) => true,
        };
        Self { seccomp_filter }
    }
}

/// Whether `status` (`/proc/self/status`) says a seccomp filter applies.
fn seccomp_filtered(status: &str) -> bool {
    status
        .lines()
        .filter_map(|line| line.strip_prefix("Seccomp:"))
        .any(|mode| mode.trim() == "2")
}

pub(super) fn refused_by_sandbox(_: &io::Error, probe: Probe) -> bool {
    probe.seccomp_filter
}

/// A process in no sandbox, for the tests.
#[cfg(test)]
pub(super) fn unconfined() -> Probe {
    Probe {
        seccomp_filter: false,
    }
}

/// The refusal a guard under `openmoat run` gets, for the tests.
#[cfg(test)]
pub(super) fn run_sandbox() -> (io::Error, Probe) {
    (
        io::Error::from_raw_os_error(13),
        Probe {
            seccomp_filter: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::seccomp_filtered;

    #[test]
    fn only_filter_mode_is_a_filter() {
        assert!(seccomp_filtered(
            "Name:\tsh\nSeccomp:\t2\nSeccomp_filters:\t2\n"
        ));
        assert!(!seccomp_filtered("Name:\tsh\nSeccomp:\t0\n"));
        assert!(!seccomp_filtered("Seccomp:\t1\n"));
        assert!(!seccomp_filtered("Name:\tsh\n"));
    }
}
