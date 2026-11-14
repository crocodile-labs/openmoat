//! Whether every copy of a host found on this machine reads the flag that
//! makes it block a call whose hook failed
//! ([`openmoat_hosts::HookSpec::block_on_failure`]).
//!
//! Claude Code runs a tool call when its `PreToolUse` hook fails to start,
//! crashes, exits with a code other than 0 or 2, or times out. Since v2.1.295 a
//! `command` hook can set `"onFailure": "block"`, and such a failure then blocks
//! the call as exit code 2 does (<https://code.claude.com/docs/en/hooks>, "Block
//! the action when a hook fails": "Requires Claude Code v2.1.295 or later").
//! The docs do not say what an older Claude Code does with a key it does not
//! know, and one hook entry its settings schema rejects can stop every hook in
//! the file from running, so `moat init` writes the key only when every copy
//! of the host that reads the file is known to be the version its spec names
//! ([`openmoat_hosts::HookFailure::flag_since`]) or later: each of its
//! programs found on `PATH` ([`openmoat_hosts::ProcessSpec::names`]) and each
//! copy an editor extension bundles ([`super::bundled`]; the VS Code extension
//! puts no `claude` on `PATH`), and at least one of them is found.

use std::process::Command;
use std::sync::{Mutex, OnceLock};

use openmoat_hosts::Host;

use super::host_version::{Version, parse, run_version};

/// Whether `host`'s entries that ask for it carry the flag that blocks a
/// failed hook's call: every copy found reads it ([`all_read`]). `false` for
/// a host whose spec names no such flag. Asked once per host and process.
pub fn blocks_on_failure(host: Host) -> bool {
    static ASKED: OnceLock<Mutex<Vec<(Host, bool)>>> = OnceLock::new();
    let Some(since) = since(host) else {
        return false;
    };
    let asked = ASKED.get_or_init(|| Mutex::new(Vec::new()));
    if let Some((_, known)) = asked
        .lock()
        .ok()
        .and_then(|a| a.iter().find(|(h, _)| *h == host).copied())
    {
        return known;
    }
    let mut versions: Vec<Option<Version>> = super::bundled::copies(host)
        .iter()
        .map(|c| Some(c.version))
        .collect();
    on_path(host, &mut versions);
    let blocks = all_read(&versions, since);
    if let Ok(mut asked) = asked.lock() {
        asked.push((host, blocks));
    }
    blocks
}

/// The version from which `host` reads the flag, when its entries ask for it.
pub fn since(host: Host) -> Option<Version> {
    let spec = host.spec();
    spec.install
        .as_ref()
        .is_some_and(|i| i.hooks.iter().any(|h| h.block_on_failure))
        .then_some(spec.hook_failure.flag_since())
        .flatten()
}

/// [`since`] as `2.1.295`, for messages; empty for a host without the flag.
pub fn since_text(host: Host) -> String {
    since(host).map_or_else(String::new, |(major, minor, patch)| {
        format!("{major}.{minor}.{patch}")
    })
}

/// Whether `version` of `host` reads the flag; `false` for a host without it.
pub fn reads_flag(host: Host, version: Version) -> bool {
    since(host).is_some_and(|since| version >= since)
}

/// Whether the copies found, each with its version (`None` when it could not
/// be read), all are `since` or later; `false` when none was found.
fn all_read(versions: &[Option<Version>], since: Version) -> bool {
    !versions.is_empty() && versions.iter().all(|v| v.is_some_and(|v| v >= since))
}

/// The variable debug builds read `host`'s version on `PATH` from instead of
/// running its programs, so end-to-end tests do not depend on the machine:
/// `MOAT_<ID>_VERSION` (`MOAT_CLAUDE_CODE_VERSION`); empty means not found.
/// The copies editor extensions bundle are still read from the home folder.
/// Release builds do not contain this check.
#[cfg(debug_assertions)]
pub fn version_variable(host: Host) -> String {
    format!(
        "MOAT_{}_VERSION",
        host.id().to_ascii_uppercase().replace('-', "_")
    )
}

/// Add each of `host`'s programs on `PATH` to `found`: its version, or `None`
/// when it does not say it.
fn on_path(host: Host, found: &mut Vec<Option<Version>>) {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(version_variable(host)) {
        let value = value.to_string_lossy();
        if !value.trim().is_empty() {
            found.push(parse(&value));
        }
        return;
    }
    for name in host.spec().process.names {
        if let Some(program) = crate::environment::find_on_path(name) {
            found.push(run_version(Command::new(program)).and_then(|text| parse(&text)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host whose entries ask for the flag, from the specs.
    fn flagged() -> Host {
        Host::ALL.into_iter().find(|h| since(*h).is_some()).unwrap()
    }

    #[test]
    fn only_the_version_the_spec_names_and_later_read_the_flag() {
        let host = flagged();
        let (major, minor, patch) = since(host).unwrap();
        assert!(reads_flag(host, (major, minor, patch)));
        assert!(reads_flag(host, (major, minor + 1, 0)));
        assert!(reads_flag(host, (major + 1, 0, 0)));
        assert!(!reads_flag(host, (major, minor, patch - 1)));
        assert_eq!(since_text(host), format!("{major}.{minor}.{patch}"));
    }

    /// The VS Code extension's copy alone is enough, as the CLI's alone is;
    /// one old or unreadable copy among them leaves the key out, and so does
    /// finding none.
    #[test]
    fn every_copy_found_must_read_the_flag() {
        let since = (2, 1, 295);
        let new = Some((2, 1, 318));
        assert!(all_read(&[new], since));
        assert!(all_read(&[new, Some((2, 1, 295))], since));
        assert!(!all_read(&[new, Some((2, 1, 200))], since));
        assert!(!all_read(&[new, None], since));
        assert!(!all_read(&[], since));
    }

    /// A host whose spec names no flag is never asked, and never gets it.
    #[test]
    fn a_host_without_the_flag_never_blocks_through_it() {
        for host in Host::ALL.into_iter().filter(|h| since(*h).is_none()) {
            assert!(!blocks_on_failure(host), "{host:?}");
            assert!(!reads_flag(host, (999, 0, 0)), "{host:?}");
            assert_eq!(since_text(host), "");
        }
    }

    #[test]
    fn the_flagged_host_has_copies_to_ask_and_a_test_variable() {
        let host = flagged();
        assert!(!host.spec().bundled.is_empty());
        assert_ne!(host.spec().process.names, &[] as &[&str]);
        assert_eq!(version_variable(host), "MOAT_CLAUDE_CODE_VERSION");
    }
}
