//! GitHub Copilot CLI hook entries: one command per
//! shell, since the CLI runs `bash` on macOS and Linux and `powershell` on
//! Windows (<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>,
//! "Command hooks"). Both name the binary by its absolute path, quoted.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, split_guard};
use crate::wire::hook_file::HookFile;

/// GitHub Copilot CLI's hook file entries.
#[derive(Debug)]
pub(crate) struct Copilot;

impl HookFile for Copilot {
    /// No `matcher`, which the CLI would reject when empty, so it runs for
    /// every tool.
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        let (binary, args) = (&guard.binary, guard.shell_args(id));
        json!({
            "type": "command",
            "bash": format!("'{}'{args}", binary.replace('\'', r"'\''")),
            "powershell": format!("& '{}'{args}", binary.replace('\'', "''")),
            "timeoutSec": spec.timeout,
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        bash(entry).is_some_and(|c| split_guard(c, id).is_some())
    }

    /// The binary `entry` runs, unquoted from its `bash` command.
    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let (quoted, _) = split_guard(bash(entry)?, id)?;
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
