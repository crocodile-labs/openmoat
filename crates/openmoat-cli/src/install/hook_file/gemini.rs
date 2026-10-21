//! The command string of OpenMoat's Gemini CLI hook entry.
//!
//! Gemini CLI runs a hook's `command` with `bash -c`, and on Windows with
//! PowerShell `-Command` (`getShellConfiguration` in
//! `packages/core/src/utils/shell-utils.ts`, `@google/gemini-cli` 0.65.0), so
//! the binary path is quoted for that shell. PowerShell runs a quoted path only
//! after the call operator `&`.
//!
//! Gemini CLI blocks the call when a hook exits with a code other than 0 or 1
//! and prints something. A binary bash cannot find exits 127 with an error
//! message, so it blocks; PowerShell exits 1 for a command it cannot find,
//! which Gemini CLI treats as a warning, so the entry exits 2 itself then
//! ([`POWERSHELL_TAIL`]), with PowerShell's message on stderr as the reason.

use std::path::Path;

/// The entry's `name`: what Gemini CLI's `/hooks` panel lists.
pub const NAME: &str = "openmoat";

/// What follows the guard on PowerShell: exit 2 when the guard could not run
/// or failed. Gemini CLI reads the guard's JSON from stdout whatever the exit
/// code, so an answer the guard printed stands.
const POWERSHELL_TAIL: &str = "; if (-not $?) { exit 2 }";

/// `binary guard --host <id>` for the shell Gemini CLI uses on this OS.
pub fn command(binary: &Path, id: &str) -> String {
    command_for(&binary.to_string_lossy(), id, cfg!(windows))
}

fn command_for(binary: &str, id: &str, powershell: bool) -> String {
    if powershell {
        let binary = binary.replace('\'', "''");
        format!("& '{binary}' guard --host {id}{POWERSHELL_TAIL}")
    } else {
        format!("'{}' guard --host {id}", binary.replace('\'', r"'\''"))
    }
}

/// The binary a command written by [`command`] runs, or `None` when the
/// command is not OpenMoat's guard for `id`.
pub fn binary_of(command: &str, id: &str) -> Option<String> {
    let suffix = format!(" guard --host {id}");
    let command = command.trim();
    let command = command.strip_suffix(POWERSHELL_TAIL).unwrap_or(command);
    let quoted = command.strip_suffix(&suffix)?.trim();
    let (quoted, powershell) = match quoted.strip_prefix("& ") {
        Some(rest) => (rest.trim(), true),
        None => (quoted, false),
    };
    let Some(inner) = quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) else {
        return Some(quoted.trim_matches('"').to_owned());
    };
    Some(if powershell {
        inner.replace("''", "'")
    } else {
        inner.replace(r"'\''", "'")
    })
}

#[cfg(test)]
mod tests;
