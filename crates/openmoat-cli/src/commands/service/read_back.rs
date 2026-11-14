//! `moat doctor` and `moat status` read the installed service file back
//! (#272): the service manager starts the proxy, the one process that enforces
//! the network policy, exactly as that file says, so a change to it after
//! `moat proxy install` changes the enforcer. The approvals listener, which
//! holds the channel's credential and the approval key, is read back the same
//! way, and refuses to start from a file this check finds anything in (ADR-094). An extra environment variable
//! (`DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`, `HTTPS_PROXY`, a second
//! `MOAT_HOME`) or a program run before it does that without touching the
//! binary or the lock. Agent writes to the service directories already need
//! review (`persistence`); this is the check a person sees afterwards.
//!
//! Pure: the caller reads the file and its mode, so the checks are tested on
//! tampered text without a real service directory.

use super::Job;

/// The environment variable a service file gets, the only one.
pub const ALLOWED_ENV: &str = "MOAT_HOME";

/// What the installed service file looks like: its bytes, and its Unix mode
/// bits where the platform has them.
pub struct Installed<'a> {
    pub text: &'a [u8],
    pub mode: Option<u32>,
}

/// Every reason the installed file is not what `moat proxy install` writes,
/// worst first; empty when it is byte for byte the file `expected` and private.
/// `environment` names the variables a file of this format sets (and anything
/// else that loads some, such as systemd's `EnvironmentFile=`), or `None` when
/// the file is not in a form it can read.
pub fn findings(
    expected: &str,
    installed: &Installed<'_>,
    environment: fn(&str) -> Option<Vec<String>>,
    job: &Job,
) -> Vec<String> {
    let mut found = Vec::new();
    match std::str::from_utf8(installed.text)
        .ok()
        .and_then(environment)
    {
        Some(names) => {
            let extra: Vec<String> = names.into_iter().filter(|n| n != ALLOWED_ENV).collect();
            if !extra.is_empty() {
                found.push(format!(
                    "sets environment {} is started with beyond `{ALLOWED_ENV}`: {}",
                    job.noun,
                    extra.join(", ")
                ));
            }
        }
        None => found.push(format!("is not in the form `{}` writes", job.install)),
    }
    if installed.text != expected.as_bytes() && found.is_empty() {
        found.push(format!(
            "differs from what `{}` writes for this binary and state directory",
            job.install
        ));
    }
    if let Some(mode) = installed.mode.filter(|m| m & 0o077 != 0) {
        found.push(format!(
            "can be read or written by others (mode {:o}, not 600)",
            mode & 0o777
        ));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::service::PROXY;

    fn findings(
        expected: &str,
        installed: &Installed<'_>,
        environment: fn(&str) -> Option<Vec<String>>,
    ) -> Vec<String> {
        super::findings(expected, installed, environment, &PROXY)
    }

    /// A stand-in format: one `NAME=value` per line.
    fn lines(text: &str) -> Option<Vec<String>> {
        text.lines()
            .map(|l| l.split_once('=').map(|(name, _)| name.to_owned()))
            .collect()
    }

    fn installed(text: &str, mode: Option<u32>) -> Installed<'_> {
        Installed {
            text: text.as_bytes(),
            mode,
        }
    }

    #[test]
    fn the_file_install_writes_has_no_finding() {
        let file = "MOAT_HOME=/h\n";
        assert_eq!(
            findings(file, &installed(file, Some(0o100_600)), lines),
            Vec::<String>::new()
        );
        assert_eq!(
            findings(file, &installed(file, None), lines),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_extra_variable_is_named() {
        let tampered = "MOAT_HOME=/h\nDYLD_INSERT_LIBRARIES=/x.dylib\n";
        let found = findings("MOAT_HOME=/h\n", &installed(tampered, Some(0o600)), lines);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("DYLD_INSERT_LIBRARIES"), "{found:?}");
    }

    #[test]
    fn any_other_change_and_an_unreadable_form_are_findings() {
        let found = findings("MOAT_HOME=/h\n", &installed("MOAT_HOME=/x\n", None), lines);
        assert!(found[0].contains("differs"), "{found:?}");
        let found = findings("MOAT_HOME=/h\n", &installed("garbage", None), lines);
        assert!(found[0].contains("not in the form"), "{found:?}");
        let binary = Installed {
            text: b"bplist00\xff",
            mode: None,
        };
        assert!(findings("x", &binary, lines)[0].contains("not in the form"));
    }

    #[test]
    fn a_mode_open_to_others_is_a_finding() {
        let file = "MOAT_HOME=/h\n";
        for mode in [0o644, 0o640, 0o666, 0o100_604] {
            let found = findings(file, &installed(file, Some(mode)), lines);
            assert_eq!(found.len(), 1, "{mode:o}: {found:?}");
            assert!(found[0].contains("not 600"), "{found:?}");
        }
        assert_eq!(
            findings(file, &installed(file, Some(0o400)), lines),
            Vec::<String>::new()
        );
    }
}
