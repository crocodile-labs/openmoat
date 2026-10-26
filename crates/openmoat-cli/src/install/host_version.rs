//! What the version of a host on this shell's search path means for
//! OpenMoat: whether it takes OpenMoat's hook
//! ([`InstallSpec::unsupported`](openmoat_hosts::InstallSpec::unsupported)),
//! and which of the host's published security advisories it is affected by
//! ([`HostSpec::advisories`](openmoat_hosts::HostSpec::advisories)).
//!
//! OpenCode 2 installs the same `opencode` program as OpenCode 1 and reads the
//! same configuration directory, but loads plugins through another API: a
//! plugin written for OpenCode 1 does not run there. Only the version the
//! program reports tells them apart, so `moat init` asks it before writing the
//! plugin, and `moat status` and `moat doctor` before calling the agent
//! protected. The same version names the advisories `moat status` and `moat
//! doctor` warn about: a flaw in the agent's own process runs where no hook
//! sees it, so an upgrade is the only fix.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use openmoat_hosts::{Advisory, Host};

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

/// One line on the published security advisories `host`'s version on the
/// search path is affected by on this system; `None` when its spec names
/// none, the program is not found, its version cannot be read, or none
/// applies.
pub fn advisory(host: Host) -> Option<String> {
    let advisories = &host.spec().advisories;
    if advisories.program.is_empty() {
        return None;
    }
    let version = version(advisories.program)?;
    let affecting: Vec<&Advisory> = advisories
        .affecting(version, crate::os_version::platform())
        .collect();
    advisory_line(host.display_name(), version, &affecting)
}

/// [`prefetch`] for every host whose directory is on this machine (in
/// `home`'s record or where its variable or default puts it).
pub fn prefetch_present(home: &crate::home::Home) {
    prefetch(
        Host::ALL.into_iter().filter(|host| {
            super::HostConfig::for_host(home, *host).is_ok_and(|c| c.host_present())
        }),
    );
}

/// Ask every host in `hosts` for its version at once, so the [`advisory`]
/// and [`unsupported`] calls that follow find them known: each program may
/// take up to the probe's limit to answer.
pub fn prefetch(hosts: impl IntoIterator<Item = Host>) {
    let mut programs: Vec<&'static str> = hosts
        .into_iter()
        .flat_map(|host| {
            let spec = host.spec();
            let gate = spec.install.as_ref().and_then(|i| i.unsupported.as_ref());
            [gate.map(|g| g.program), Some(spec.advisories.program)]
        })
        .flatten()
        .filter(|program| !program.is_empty())
        .collect();
    programs.sort_unstable();
    programs.dedup();
    std::thread::scope(|scope| {
        for program in programs {
            scope.spawn(move || version(program));
        }
    });
}

/// The warning for `name` at `version` affected by `affecting` (in its
/// spec's order): the first one by id and summary, how many more, the
/// version that fixes them all and where the first is published.
fn advisory_line(name: &str, version: Version, affecting: &[&Advisory]) -> Option<String> {
    let first = affecting.first()?;
    let fixed = affecting.iter().map(|a| a.fixed).max()?;
    let more = match affecting.len() - 1 {
        0 => String::new(),
        1 => " and 1 more".to_owned(),
        n => format!(" and {n} more"),
    };
    Some(format!(
        "{name} {} has a known security advisory, {} ({}){more}; upgrade to {} or later: {}",
        dotted(version),
        first.id,
        first.summary,
        dotted(fixed),
        first.source
    ))
}

fn dotted((major, minor, patch): Version) -> String {
    format!("{major}.{minor}.{patch}")
}

/// The version `program` reports, asked once per process.
fn version(program: &'static str) -> Option<Version> {
    static ASKED: OnceLock<Asked> = OnceLock::new();
    let asked = ASKED.get_or_init(|| Mutex::new(Vec::new()));
    if let Some((_, known)) = asked.lock().ok()?.iter().find(|(name, _)| *name == program) {
        return *known;
    }
    let found = ask(program);
    let mut asked = asked.lock().ok()?;
    if !asked.iter().any(|(name, _)| *name == program) {
        asked.push((program, found));
    }
    found
}

fn ask(program: &str) -> Option<Version> {
    // Debug builds read `MOAT_<PROGRAM>_VERSION` instead of running the
    // program, so end-to-end tests do not depend on the machine; empty means
    // not found. Release builds do not contain this check.
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(format!("MOAT_{}_VERSION", program.to_uppercase())) {
        return parse_any(&value.to_string_lossy());
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let found = crate::environment::find_in(&path, &[], program)?;
    parse_any(&run_version(Command::new(found))?)
}

/// The first word of `text` that reads as a version: `1.19.4`, and also
/// `codex-cli 0.164.0` or `Hermes Agent v0.22.5`, whose first word is a name.
fn parse_any(text: &str) -> Option<Version> {
    text.split_whitespace().find_map(parse)
}

#[cfg(test)]
mod tests;
