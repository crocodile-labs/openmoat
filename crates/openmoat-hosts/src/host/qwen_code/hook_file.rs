//! Qwen Code's `settings.json` entries: Claude Code's nested layout, one
//! named command hook whose `command` is a shell string and whose `timeout`
//! is in seconds (`CommandHookConfig` in `packages/core/src/hooks/types.ts`;
//! the hooks page: a value of 1000 or more is read as milliseconds).
//!
//! A hook's `shell` is `bash` or `powershell`. The entry names PowerShell on
//! Windows and quotes the binary for it, with the tail that exits 2 when the
//! guard could not run (PowerShell exits 1 for a missing command, which Qwen
//! Code would read as a non-blocking error); elsewhere it leaves Qwen Code's
//! default and quotes the binary for `sh`.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, fail_safe_command, sh_binary};
use crate::wire::hook_file::HookFile;

/// Qwen Code's `settings.json` entries.
#[derive(Debug)]
pub(crate) struct Qwen;

/// The entry's `name`, as Qwen Code lists its hooks.
const NAME: &str = "openmoat";

impl HookFile for Qwen {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        entry(spec, id, guard, cfg!(windows))
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| sh_binary(c, id).is_some())
                })
            })
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        sh_binary(entry.pointer("/hooks/0/command").and_then(Value::as_str)?, id)
    }
}

/// The entry for `spec`, its command for PowerShell when `powershell`.
pub(super) fn entry(spec: &HookSpec, id: &str, guard: &GuardCommand, powershell: bool) -> Value {
    let mut hook = json!({
        "name": NAME,
        "type": "command",
        "command": fail_safe_command(guard, id, powershell),
        "timeout": spec.timeout,
    });
    if powershell {
        hook["shell"] = Value::from("powershell");
    }
    json!({ "matcher": spec.matcher, "hooks": [hook] })
}
