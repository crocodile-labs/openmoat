//! Hermes Agent's `hooks.pre_tool_call` entries in `config.yaml`:
//! `{command, timeout, fail_closed}`, no `matcher`, so the hook runs for every
//! tool.
//!
//! Hermes splits `command` into words itself and runs it without a shell
//! (`split_command_line` in `hermes_cli/_subprocess_compat.py`: `shlex.split`
//! on POSIX; on Windows `shlex` without escapes, one layer of matching quotes
//! taken off each word), so the binary path is quoted in single quotes on
//! POSIX and in double quotes on Windows, where a path cannot hold one. The
//! person's consent is keyed on this exact string
//! (`shell-hooks-allowlist.json`, [`super::consent`]).

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::hook_file::{HookFile, guard_args};

/// Hermes Agent's `config.yaml` entries.
#[derive(Debug)]
pub(crate) struct Hermes;

impl HookFile for Hermes {
    /// `fail_closed: true` on every entry: without it Hermes runs the call
    /// when the hook cannot start, times out or answers garbage.
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        json!({
            "command": command_for(binary, id, cfg!(windows)),
            "timeout": spec.timeout,
            "fail_closed": true,
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        command(entry).is_some_and(|c| binary_of(c, id).is_some())
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        binary_of(command(entry)?, id)
    }

    /// Hermes reads `fail_closed`, a YAML boolean; any other value it takes as
    /// `false` (`_parse_spec` in `agent/shell_hooks.py`).
    fn fail_closed_key(&self) -> Option<&'static str> {
        Some("fail_closed")
    }
}

fn command(entry: &Value) -> Option<&str> {
    entry.get("command").and_then(Value::as_str)
}

/// `binary guard --host <id>`, the binary quoted for Windows or for POSIX.
pub(super) fn command_for(binary: &str, id: &str, windows: bool) -> String {
    let args = guard_args(id);
    if windows {
        format!("\"{binary}\"{args}")
    } else {
        format!("'{}'{args}", binary.replace('\'', r"'\''"))
    }
}

/// The binary a command written by [`command_for`] runs, or `None` when the
/// command is not OpenMoat's guard for `id`.
pub(super) fn binary_of(command: &str, id: &str) -> Option<String> {
    let quoted = command.trim().strip_suffix(&guard_args(id))?.trim();
    if let Some(inner) = quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"')) {
        return Some(inner.to_owned());
    }
    Some(
        match quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
            Some(inner) => inner.replace(r"'\''", "'"),
            None => quoted.to_owned(),
        },
    )
}
