//! Antigravity CLI's hook file layout: one named top-level entry per hook,
//! `{ "openmoat": { "enabled": true, "PreToolUse": [ { "matcher", "hooks":
//! [ { "type": "command", "command", "timeout" } ] } ] } }`. The `timeout` is
//! in seconds, and `command` is a shell string.
//!
//! The shell is not documented, so on Unix the binary is quoted for a POSIX
//! shell, and on Windows, where neither `cmd` nor PowerShell can be assumed,
//! left bare when a shell would not split it and double-quoted when it would
//! (which `cmd` reads and PowerShell does not, so a binary under such a path
//! cannot be promised to run; `HOST.md` says so).

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, split_guard};
use crate::wire::hook_file::HookFile;

/// OpenMoat's hook's name, the top-level key of the file.
pub(crate) const NAME: &str = "openmoat";

/// Antigravity CLI's layout.
#[derive(Debug)]
pub(crate) struct Named;

impl HookFile for Named {
    fn section(&self) -> &'static str {
        NAME
    }

    /// `"enabled": false` disables a hook "without removing it".
    fn section_switch(&self) -> Option<&'static str> {
        Some("enabled")
    }

    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        json!({
            "matcher": spec.matcher,
            "hooks": [{
                "type": "command",
                "command": command_for(guard, id, cfg!(windows)),
                "timeout": spec.timeout,
            }],
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .pointer("/hooks/0/command")
            .and_then(Value::as_str)
            .is_some_and(|c| binary_of(c, id).is_some())
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        binary_of(entry.pointer("/hooks/0/command").and_then(Value::as_str)?, id)
    }
}

/// `binary guard --host <id> --home <state directory>`, for the host's shell.
fn command_for(guard: &GuardCommand, id: &str, windows: bool) -> String {
    let args = guard.shell_args(id);
    if !windows {
        return format!("'{}'{args}", guard.binary.replace('\'', r"'\''"));
    }
    if guard.binary.contains(char::is_whitespace) {
        format!("\"{}\"{args}", guard.binary)
    } else {
        format!("{}{args}", guard.binary)
    }
}

/// The binary a [`command_for`] command runs, or `None` when the command is
/// not OpenMoat's guard for `id`.
fn binary_of(command: &str, id: &str) -> Option<String> {
    let (quoted, _) = split_guard(command, id)?;
    Some(match quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
        Some(inner) => inner.replace(r"'\''", "'"),
        None => quoted.trim_matches('"').to_owned(),
    })
}

#[cfg(test)]
mod tests;
