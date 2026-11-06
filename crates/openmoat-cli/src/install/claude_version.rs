//! Whether the Claude Code on this shell's search path knows `onFailure`.
//!
//! Claude Code runs a tool call when its `PreToolUse` hook fails to start,
//! crashes, exits with a code other than 0 or 2, or times out. Since v2.1.295 a
//! `command` hook can set `"onFailure": "block"`, and such a failure then blocks
//! the call as exit code 2 does (<https://code.claude.com/docs/en/hooks>, "Block
//! the action when a hook fails": "Requires Claude Code v2.1.295 or later").
//! The docs do not say what an older Claude Code does with a key it does not
//! know, and one hook entry its settings schema rejects can stop every hook in
//! the file from running, so `moat init` writes the key only when every
//! Claude Code that reads the file is known to be that version or later: the
//! `claude` found on `PATH` and each copy an editor extension bundles
//! ([`super::bundled`]; the VS Code extension puts no `claude` on `PATH`), and
//! at least one of them is found.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use openmoat_hosts::Host;

/// The first Claude Code release that reads `onFailure`.
const ON_FAILURE_SINCE: Version = (2, 1, 295);
/// How long `claude --version` may take before it counts as unknown.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the probe checks whether `claude --version` has exited.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(super) type Version = (u64, u64, u64);

/// Debug builds read the version of the `claude` on `PATH` from
/// `MOAT_CLAUDE_CODE_VERSION` instead of running it, so end-to-end tests do
/// not depend on the machine; empty means not found. The copies editor
/// extensions bundle are still read from the home folder. Release builds do
/// not contain this check.
#[cfg(debug_assertions)]
const VERSION_OVERRIDE: &str = "MOAT_CLAUDE_CODE_VERSION";

/// Whether Claude Code honours `"onFailure": "block"` on a hook: every copy
/// found reads it ([`all_read_on_failure`]). Asked once per process.
pub fn blocks_on_failure() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let bundled = blocking_host()
            .map(super::bundled::copies)
            .unwrap_or_default();
        let mut versions: Vec<Option<Version>> = bundled.iter().map(|c| Some(c.version)).collect();
        on_path(&mut versions);
        all_read_on_failure(&versions)
    })
}

/// The host whose hook entries ask to block a call whose hook failed
/// (`HookSpec::block_on_failure`): Claude Code.
fn blocking_host() -> Option<Host> {
    Host::ALL.into_iter().find(|host| {
        host.spec()
            .install
            .as_ref()
            .is_some_and(|i| i.hooks.iter().any(|h| h.block_on_failure))
    })
}

/// Whether the copies found, each with its version (`None` when it could not
/// be read), all read `onFailure`; `false` when none was found.
fn all_read_on_failure(versions: &[Option<Version>]) -> bool {
    !versions.is_empty() && versions.iter().all(|v| v.is_some_and(supports_on_failure))
}

/// The minimum version that reads `onFailure`, for messages.
pub fn on_failure_since() -> String {
    let (major, minor, patch) = ON_FAILURE_SINCE;
    format!("{major}.{minor}.{patch}")
}

/// Whether `version` reads `onFailure`.
pub(super) fn supports_on_failure(version: Version) -> bool {
    version >= ON_FAILURE_SINCE
}

/// Add the `claude` on `PATH` to `found` when there is one: its version, or
/// `None` when it does not say it.
fn on_path(found: &mut Vec<Option<Version>>) {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(VERSION_OVERRIDE) {
        let value = value.to_string_lossy();
        if !value.trim().is_empty() {
            found.push(parse(&value));
        }
        return;
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(claude) = crate::environment::find_in(&path, &[], "claude") {
        found.push(run_version(Command::new(claude)).and_then(|text| parse(&text)));
    }
}

/// The standard output of `command --version`, or `None` when it cannot start,
/// fails, or takes longer than [`PROBE_TIMEOUT`].
pub(super) fn run_version(mut command: Command) -> Option<String> {
    let mut child = command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if Instant::now() >= deadline => {
                // Best effort: the probe is abandoned whether or not the kill lands.
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
        }
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut text).ok()?;
    Some(text)
}

/// `2.1.295 (Claude Code)` as `(2, 1, 295)`; a pre-release or build suffix on
/// the last number (`2.1.295-beta.1`) is ignored.
pub(super) fn parse(text: &str) -> Option<Version> {
    let first = text.split_whitespace().next()?;
    let mut parts = first.trim_start_matches('v').splitn(3, '.');
    let number = |part: Option<&str>| -> Option<u64> {
        let digits: String = part?.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    Some((
        number(parts.next())?,
        number(parts.next())?,
        number(parts.next())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_claude_version_prints() {
        assert_eq!(parse("2.1.295 (Claude Code)\n"), Some((2, 1, 295)));
        assert_eq!(parse("v2.2.0"), Some((2, 2, 0)));
        assert_eq!(parse("2.1.300-beta.1 (Claude Code)"), Some((2, 1, 300)));
        assert_eq!(parse(""), None);
        assert_eq!(parse("Claude Code"), None);
        assert_eq!(parse("2.1"), None);
    }

    #[test]
    fn only_v2_1_295_and_later_get_on_failure() {
        assert!(supports_on_failure((2, 1, 295)));
        assert!(supports_on_failure((2, 2, 0)));
        assert!(supports_on_failure((3, 0, 0)));
        assert!(!supports_on_failure((2, 1, 294)));
        assert!(!supports_on_failure((2, 0, 999)));
        assert!(!supports_on_failure((1, 9, 400)));
    }

    /// The VS Code extension's copy alone is enough, as the CLI's alone is;
    /// one old or unreadable copy among them leaves the key out, and so does
    /// finding none.
    #[test]
    fn every_copy_found_must_read_on_failure() {
        let new = Some((2, 1, 318));
        assert!(all_read_on_failure(&[new]));
        assert!(all_read_on_failure(&[new, Some((2, 1, 295))]));
        assert!(!all_read_on_failure(&[new, Some((2, 1, 200))]));
        assert!(!all_read_on_failure(&[new, None]));
        assert!(!all_read_on_failure(&[]));
        assert_eq!(on_failure_since(), "2.1.295");
    }

    #[test]
    fn the_blocking_host_is_the_one_whose_entries_ask_for_it() {
        let host = blocking_host().unwrap();
        assert!(!host.spec().bundled.is_empty());
    }
}
