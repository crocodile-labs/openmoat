//! GitHub Copilot CLI hook entries (`HookFormat::Copilot`): one command per
//! shell, since the CLI runs `bash` on macOS and Linux and `powershell` on
//! Windows (<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>,
//! "Command hooks"). Both name the binary by its absolute path, quoted.

use std::path::Path;

use serde_json::{Value, json};

use crate::install::{HookSpec, HostConfig};

/// The [`crate::install::HookFormat::Copilot`] entry for `spec`: no `matcher`, which the CLI would reject when empty,
/// so it runs for every tool.
pub(super) fn entry(config: &HostConfig, spec: &HookSpec, binary: &Path) -> Value {
    let path = binary.to_string_lossy();
    let args = guard_args(config);
    json!({
        "type": "command",
        "bash": format!("'{}'{args}", path.replace('\'', r"'\''")),
        "powershell": format!("& '{}'{args}", path.replace('\'', "''")),
        "timeoutSec": spec.timeout,
    })
}

fn guard_args(config: &HostConfig) -> String {
    format!(" guard --host {}", config.host.id())
}

/// Whether `entry` runs `moat guard` for this host.
pub(super) fn is_ours(entry: &Value, config: &HostConfig) -> bool {
    bash(entry).is_some_and(|c| c.trim_end().ends_with(&guard_args(config)))
}

/// The binary `entry` runs, unquoted from its `bash` command.
pub(super) fn binary(entry: &Value, config: &HostConfig) -> Option<String> {
    let quoted = bash(entry)?
        .trim_end()
        .strip_suffix(&guard_args(config))?
        .trim();
    Some(
        match quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
            Some(inner) => inner.replace(r"'\''", "'"),
            None => quoted.to_owned(),
        },
    )
}

fn bash(entry: &Value) -> Option<&str> {
    entry.get("bash").and_then(Value::as_str)
}

#[cfg(test)]
mod tests;
