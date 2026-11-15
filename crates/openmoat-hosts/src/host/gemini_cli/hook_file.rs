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
//! ([`crate::wire::guard_command::POWERSHELL_TAIL`]), with PowerShell's
//! message on stderr as the reason.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::GuardCommand;
/// `binary guard --host <id>` for bash, or for PowerShell, and the binary it
/// runs; Gemini CLI reads the guard's JSON from stdout whatever the exit code,
/// so an answer the guard printed stands.
pub(super) use crate::wire::guard_command::{sh_binary as binary_of, shell_command as command_for};
use crate::wire::hook_file::HookFile;

/// Gemini CLI's `settings.json` entries.
#[derive(Debug)]
pub(crate) struct Gemini;

/// The entry's `name`: what Gemini CLI's `/hooks` panel lists.
const NAME: &str = "openmoat";

impl HookFile for Gemini {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        json!({
            "matcher": spec.matcher,
            "hooks": [{
                "name": NAME,
                "type": "command",
                "command": command_for(guard, id, cfg!(windows)),
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

#[cfg(test)]
mod tests;
