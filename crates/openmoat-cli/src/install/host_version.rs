//! Whether the version of a host on this shell's search path takes OpenMoat's
//! hook ([`InstallSpec::unsupported`](openmoat_hosts::InstallSpec::unsupported)).
//!
//! OpenCode 2 installs the same `opencode` program as OpenCode 1 and reads the
//! same configuration directory, but loads plugins through another API: a
//! plugin written for OpenCode 1 does not run there. Only the version the
//! program reports tells them apart, so `moat init` asks it before writing the
//! plugin, and `moat status` and `moat doctor` before calling the agent
//! protected.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use openmoat_hosts::Host;

use super::claude_version::{Version, parse, run_version};

/// The versions asked so far in this process, by program.
type Asked = Mutex<Vec<(&'static str, Option<Version>)>>;

/// Why `host`'s version on the search path does not take OpenMoat's hook, as
/// one line; `None` when its spec names no such versions, when no program is
/// found or its version cannot be read (a host OpenMoat cannot ask is set up as
/// one that takes the hook), or when it is a supported one.
pub fn unsupported(host: Host) -> Option<String> {
    let gate = host.spec().install.as_ref()?.unsupported.as_ref()?;
    let version = version(gate.program)?;
    (version.0 >= gate.from_major).then(|| {
        let (major, minor, patch) = version;
        format!(
            "`{} --version` reports {major}.{minor}.{patch}: {}",
            gate.program, gate.why
        )
    })
}

/// The version `program` reports, asked once per process.
fn version(program: &'static str) -> Option<Version> {
    static ASKED: OnceLock<Asked> = OnceLock::new();
    let asked = ASKED.get_or_init(|| Mutex::new(Vec::new()));
    if let Some((_, known)) = asked.lock().ok()?.iter().find(|(name, _)| *name == program) {
        return *known;
    }
    let found = ask(program);
    asked.lock().ok()?.push((program, found));
    found
}

fn ask(program: &str) -> Option<Version> {
    // Debug builds read `MOAT_<PROGRAM>_VERSION` instead of running the
    // program, so end-to-end tests do not depend on the machine; empty means
    // not found. Release builds do not contain this check.
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(format!("MOAT_{}_VERSION", program.to_uppercase())) {
        return parse(&value.to_string_lossy());
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let found = crate::environment::find_in(&path, &[], program)?;
    parse(&run_version(Command::new(found))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OpenCode 1 takes the plugin; OpenCode 2 does not, and says why.
    #[test]
    fn only_versions_from_the_spec_major_are_unsupported() {
        let gate = Host::ALL
            .iter()
            .find_map(|h| h.spec().install.as_ref()?.unsupported.as_ref())
            .unwrap();
        assert_eq!(gate.from_major, 2);
        assert!(!gate.why.is_empty());
        assert!(parse("1.19.4").is_some_and(|v| v.0 < gate.from_major));
        assert!(parse("2.1.4").is_some_and(|v| v.0 >= gate.from_major));
    }
}
