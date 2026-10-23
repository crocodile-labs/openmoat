//! Gemini CLI's `settings.json` entries: the nested
//! layout with one named hook whose `command` is a shell string and whose
//! `timeout` is in milliseconds.
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

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::hook_file::HookFile;

/// Gemini CLI's `settings.json` entries.
#[derive(Debug)]
pub(crate) struct Gemini;

/// The entry's `name`: what Gemini CLI's `/hooks` panel lists.
const NAME: &str = "openmoat";

/// What follows the guard on PowerShell: exit 2 when the guard could not run
/// or failed. Gemini CLI reads the guard's JSON from stdout whatever the exit
/// code, so an answer the guard printed stands.
const POWERSHELL_TAIL: &str = "; if (-not $?) { exit 2 }";

impl HookFile for Gemini {
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        json!({
            "matcher": spec.matcher,
            "hooks": [{
                "name": NAME,
                "type": "command",
                "command": command_for(binary, id, cfg!(windows)),
                "timeout": spec.timeout * 1000,
            }],
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| binary_of(c, id).is_some())
                })
            })
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let command = entry.pointer("/hooks/0/command").and_then(Value::as_str)?;
        binary_of(command, id)
    }
}

/// `binary guard --host <id>` for bash, or for PowerShell.
fn command_for(binary: &str, id: &str, powershell: bool) -> String {
    if powershell {
        let binary = binary.replace('\'', "''");
        format!("& '{binary}' guard --host {id}{POWERSHELL_TAIL}")
    } else {
        format!("'{}' guard --host {id}", binary.replace('\'', r"'\''"))
    }
}

/// The binary a command written by [`command_for`] runs, or `None` when the
/// command is not OpenMoat's guard for `id`.
fn binary_of(command: &str, id: &str) -> Option<String> {
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
