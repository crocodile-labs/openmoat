//! GitHub Copilot CLI hook entries: one command per
//! shell, since the CLI runs `bash` on macOS and Linux and `powershell` on
//! Windows (<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>,
//! "Command hooks"). Both name the binary by its absolute path, quoted.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::hook_file::{HookFile, guard_args};

/// GitHub Copilot CLI's hook file entries.
#[derive(Debug)]
pub(crate) struct Copilot;

impl HookFile for Copilot {
    /// No `matcher`, which the CLI would reject when empty, so it runs for
    /// every tool.
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        let args = guard_args(id);
        json!({
            "type": "command",
            "bash": format!("'{}'{args}", binary.replace('\'', r"'\''")),
            "powershell": format!("& '{}'{args}", binary.replace('\'', "''")),
            "timeoutSec": spec.timeout,
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        bash(entry).is_some_and(|c| c.trim_end().ends_with(&guard_args(id)))
    }

    /// The binary `entry` runs, unquoted from its `bash` command.
    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let quoted = bash(entry)?.trim_end().strip_suffix(&guard_args(id))?.trim();
        Some(
            match quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
                Some(inner) => inner.replace(r"'\''", "'"),
                None => quoted.to_owned(),
            },
        )
    }

    fn has_version(&self) -> bool {
        true
    }
}

fn bash(entry: &Value) -> Option<&str> {
    entry.get("bash").and_then(Value::as_str)
}
