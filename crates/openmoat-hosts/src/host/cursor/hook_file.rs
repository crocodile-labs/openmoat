//! Cursor's `hooks.json` entries:
//! `{"version": 1, "hooks": {"<event>": [{"command": "<shell string>",
//! "timeout", "failClosed"}]}}`. Cursor is fail-open unless `failClosed` is
//! set, so every entry sets it.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::hook_file::{HookFile, guard_args};

/// Cursor's `hooks.json` entries.
#[derive(Debug)]
pub(crate) struct Cursor;

impl HookFile for Cursor {
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        json!({
            "command": command(binary, id),
            "timeout": spec.timeout,
            "failClosed": true,
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| c.trim_end().ends_with(&guard_args(id)))
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let quoted = entry
            .get("command")?
            .as_str()?
            .trim_end()
            .strip_suffix(&guard_args(id))?;
        Some(quoted.trim().trim_matches('"').replace("\\\"", "\""))
    }

    fn has_version(&self) -> bool {
        true
    }
}

/// Cursor takes one shell string; the binary path is quoted so spaces survive.
fn command(binary: &str, id: &str) -> String {
    let path = binary.replace('"', "\\\"");
    format!("\"{path}\" guard --host {id}")
}
